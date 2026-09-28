// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// Jeu d'essai : deux sources visent un nom d'hôte de la box et une adresse de
// la box (plages de documentation, RFC 5737). Aucune de ces chaînes ne doit
// apparaître dans la vue réduite.
var (
	sourcesEssai = []string{"203.0.113.9", "198.51.100.7"}
	ciblesEssai  = []string{"git.gk2.secubox.in", "192.0.2.10:443"}
	// Tout ce qui ressemble à une adresse IPv4, où que ce soit dans le corps.
	motifIPv4 = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

// Les deux arbres sous lesquels l'API est servie : préfixé (relais du Hall) et
// racine (agrégateur, vhost actor.gk2).
var prefixes = []string{"/api/v1/actor", ""}

// variantesReduites rend, pour un arbre, des en-têtes de vue qui doivent tous
// donner la vue réduite. nil = en-tête absent.
func variantesReduites(p string) []*string {
	v := []*string{nil, ptr("reduite"), ptr("")}
	if p != "" {
		// Arbre préfixé : même la valeur de la vue complète n'y ouvre rien.
		v = append(v, ptr(valeurComplete))
	}
	return v
}

func nomVariante(p string, v *string) string {
	if v == nil {
		return p + " [sans en-tête]"
	}
	return p + " [" + *v + "]"
}

// complete est l'en-tête posé par les routes d'administration.
var complete = ptr(valeurComplete)

// serveurPeuple rend un serveur dont le graphe porte au moins une campagne, et
// l'identifiant d'une preuve présente au ledger.
func serveurPeuple(t *testing.T) (*Server, string) {
	t.Helper()
	s := serveur(t)
	now := time.Now().Unix()
	var preuve string
	for i, src := range sourcesEssai {
		for j, cible := range ciblesEssai {
			e := &envelope.Envelope{
				EventID: envelope.NewEventID(), Timestamp: now - int64(10*(i+j)),
				Sensor: envelope.SensorWAF, SrcIP: src, DstService: cible,
				Action: envelope.ActionBlock, Severity: 70,
				PathShape: "/wp-login.php", UserAgentFamily: "python-requests",
				RequestRateBucket: "burst",
			}
			if err := e.Validate(); err != nil {
				t.Fatalf("enveloppe d'essai invalide : %v", err)
			}
			s.correlate(e)
			preuve = e.EventID
		}
	}
	if _, ok, _ := s.ledger.Get(preuve); !ok {
		t.Fatal("précondition : la preuve d'essai est absente du ledger")
	}
	return s, preuve
}

func appel(t *testing.T, s *Server, methode, chemin string, entete *string, corps string) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if corps != "" {
		body = strings.NewReader(corps)
	}
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(methode, chemin, body)
	} else {
		req = httptest.NewRequest(methode, chemin, nil)
	}
	if entete != nil {
		req.Header.Set(enteteVue, *entete)
	}
	w := httptest.NewRecorder()
	s.apiMux().ServeHTTP(w, req)
	return w
}

func ptr(s string) *string { return &s }

// sansDonneeInterne vérifie qu'un corps ne contient ni source, ni cible, ni
// quoi que ce soit qui ressemble à une adresse IPv4 ou à un nom de la box.
func sansDonneeInterne(t *testing.T, route string, corps []byte) {
	t.Helper()
	for _, x := range append(append([]string{}, sourcesEssai...), ciblesEssai...) {
		if bytes.Contains(corps, []byte(x)) {
			t.Errorf("%s : %q présent dans la vue réduite", route, x)
		}
	}
	for _, x := range []string{"gk2", "secubox.in", "192.0.2."} {
		if bytes.Contains(corps, []byte(x)) {
			t.Errorf("%s : %q présent dans la vue réduite", route, x)
		}
	}
	if m := motifIPv4.Find(corps); m != nil {
		t.Errorf("%s : adresse %q présente dans la vue réduite", route, m)
	}
}

// clesInterdites : aucune de ces clés n'existe dans la vue réduite, à aucun niveau.
var clesInterdites = []string{"targets", "cibles", "tl", "evidence", "evidence_refs", "ips_list"}

func sansCle(t *testing.T, route string, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, sous := range x {
			for _, c := range clesInterdites {
				if k == c {
					t.Errorf("%s : clé %q présente dans la vue réduite", route, k)
				}
			}
			sansCle(t, route, sous)
		}
	case []any:
		for _, sous := range x {
			sansCle(t, route, sous)
		}
	}
}

func TestVue_ReduiteActeursSansCibleNiAdresse(t *testing.T) {
	s, _ := serveurPeuple(t)
	for _, p := range prefixes {
		for _, v := range variantesReduites(p) {
			nom := nomVariante(p+"/actors", v)
			w := appel(t, s, http.MethodGet, p+"/actors", v, "")
			if w.Code != http.StatusOK {
				t.Fatalf("%s : HTTP %d", nom, w.Code)
			}
			sansDonneeInterne(t, nom, w.Body.Bytes())
			var acts []map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &acts); err != nil {
				t.Fatal(err)
			}
			if len(acts) == 0 {
				t.Fatalf("%s : aucun acteur dans la vue réduite", nom)
			}
			sansCle(t, nom, acts)
			// La forme utile reste : priorité, vecteur, compteurs.
			for _, a := range acts {
				if a["id"] == "" || a["vec"] == nil || a["src"] == nil || a["priority"] == nil {
					t.Errorf("%s : projection réduite incomplète : %v", nom, a)
				}
				if n, _ := a["nb_cibles"].(float64); n < 1 {
					t.Errorf("%s : nb_cibles = %v, attendu ≥ 1", nom, a["nb_cibles"])
				}
			}
		}
	}
}

func TestVue_ReduiteActeurUnitaireSansCible(t *testing.T) {
	s, _ := serveurPeuple(t)
	var acts []map[string]any
	_ = json.Unmarshal(appel(t, s, http.MethodGet, "/actors", complete, "").Body.Bytes(), &acts)
	if len(acts) == 0 {
		t.Fatal("précondition : aucun acteur")
	}
	id := acts[0]["id"].(string)
	for _, p := range prefixes {
		for _, v := range variantesReduites(p) {
			nom := nomVariante(p+"/actors/{id}", v)
			w := appel(t, s, http.MethodGet, p+"/actors/"+id, v, "")
			if w.Code != http.StatusOK {
				t.Fatalf("%s : HTTP %d", nom, w.Code)
			}
			sansDonneeInterne(t, nom, w.Body.Bytes())
			var a map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
				t.Fatal(err)
			}
			sansCle(t, nom, a)
			if a["id"] != id {
				t.Errorf("%s : id = %v", nom, a["id"])
			}
			if w := appel(t, s, http.MethodGet, p+"/actors/ACT-9999", v, ""); w.Code != http.StatusNotFound {
				t.Errorf("%s ACT-9999 : HTTP %d, attendu 404", nom, w.Code)
			}
		}
	}
}

func TestVue_ReduiteCampagnesSansCibleNiSignatureDerivee(t *testing.T) {
	s, _ := serveurPeuple(t)
	var completes []map[string]any
	_ = json.Unmarshal(appel(t, s, http.MethodGet, "/campaigns", complete, "").Body.Bytes(), &completes)
	if len(completes) == 0 {
		t.Fatal("précondition : aucune campagne dans le jeu d'essai")
	}
	sigCompletes := map[string]bool{}
	for _, c := range completes {
		sigCompletes[c["signature"].(string)] = true
	}
	for _, p := range prefixes {
		for _, v := range variantesReduites(p) {
			nom := nomVariante(p+"/campaigns", v)
			w := appel(t, s, http.MethodGet, p+"/campaigns", v, "")
			if w.Code != http.StatusOK {
				t.Fatalf("%s : HTTP %d", nom, w.Code)
			}
			sansDonneeInterne(t, nom, w.Body.Bytes())
			var red []map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &red); err != nil {
				t.Fatal(err)
			}
			if len(red) != len(completes) {
				t.Fatalf("%s : %d groupes, attendu %d", nom, len(red), len(completes))
			}
			sansCle(t, nom, red)
			for _, c := range red {
				sig, _ := c["signature"].(string)
				if sig == "" || sigCompletes[sig] {
					t.Errorf("%s : signature %q non opaque", nom, sig)
				}
				if n, _ := c["nb_cibles"].(float64); int(n) != len(ciblesEssai) {
					t.Errorf("%s : nb_cibles = %v, attendu %d", nom, c["nb_cibles"], len(ciblesEssai))
				}
			}
		}
	}
	// L'identifiant opaque reste stable d'un appel à l'autre (clé du rendu).
	a := appel(t, s, http.MethodGet, "/api/v1/actor/campaigns", nil, "").Body.String()
	b := appel(t, s, http.MethodGet, "/api/v1/actor/campaigns", nil, "").Body.String()
	if a != b {
		t.Error("la vue réduite des campagnes change d'un appel à l'autre")
	}
}

func TestVue_ReduitePreuveEtFeedbackAbsents(t *testing.T) {
	s, preuve := serveurPeuple(t)
	avant, _ := s.ledger.Count()
	inconnue := appel(t, s, http.MethodGet, "/api/v1/actor/route-inexistante", nil, "")
	for _, p := range prefixes {
		for _, v := range variantesReduites(p) {
			nom := nomVariante(p, v)
			w := appel(t, s, http.MethodGet, p+"/evidence/"+preuve, v, "")
			if w.Code != http.StatusNotFound {
				t.Errorf("%s/evidence : HTTP %d, attendu 404", nom, w.Code)
			}
			// Indiscernable d'une route qui n'existe pas.
			if w.Body.String() != inconnue.Body.String() {
				t.Errorf("%s/evidence : corps %q, attendu celui d'une route inconnue %q", nom, w.Body.String(), inconnue.Body.String())
			}
			w = appel(t, s, http.MethodPost, p+"/feedback/ACT-0001", v, `{"label":"unknown"}`)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s/feedback : HTTP %d, attendu 404", nom, w.Code)
			}
		}
	}
	if apres, _ := s.ledger.Count(); apres != avant {
		t.Errorf("le ledger a changé dans la vue réduite : %d → %d", avant, apres)
	}
}

func TestVue_StatsIdentiquesDansLesDeuxVues(t *testing.T) {
	s, _ := serveurPeuple(t)
	wc := appel(t, s, http.MethodGet, "/stats", complete, "")
	if wc.Code != http.StatusOK {
		t.Fatalf("/stats (vue complète) : HTTP %d", wc.Code)
	}
	var c map[string]any
	_ = json.Unmarshal(wc.Body.Bytes(), &c)
	bc, _ := json.Marshal(c)
	for _, p := range prefixes {
		for _, v := range variantesReduites(p) {
			nom := nomVariante(p+"/stats", v)
			wr := appel(t, s, http.MethodGet, p+"/stats", v, "")
			if wr.Code != http.StatusOK {
				t.Fatalf("%s : HTTP %d", nom, wr.Code)
			}
			var r map[string]any
			_ = json.Unmarshal(wr.Body.Bytes(), &r)
			br, _ := json.Marshal(r)
			if !bytes.Equal(bc, br) {
				t.Errorf("%s diffère de la vue complète :\n%s\n%s", nom, bc, br)
			}
		}
	}
}

func TestVue_ArbrePrefixeToujoursReduit(t *testing.T) {
	// L'arbre des relais qui recopient le chemin : aucun en-tête n'y ouvre la
	// vue complète, pas même celui des routes d'administration.
	s, preuve := serveurPeuple(t)
	avant, _ := s.ledger.Count()
	w := appel(t, s, http.MethodGet, "/api/v1/actor/actors", complete, "")
	sansDonneeInterne(t, "/api/v1/actor/actors [complete]", w.Body.Bytes())
	w = appel(t, s, http.MethodGet, "/api/v1/actor/campaigns", complete, "")
	sansDonneeInterne(t, "/api/v1/actor/campaigns [complete]", w.Body.Bytes())
	if w := appel(t, s, http.MethodGet, "/api/v1/actor/evidence/"+preuve, complete, ""); w.Code != http.StatusNotFound {
		t.Errorf("/api/v1/actor/evidence [complete] : HTTP %d, attendu 404", w.Code)
	}
	if w := appel(t, s, http.MethodPost, "/api/v1/actor/feedback/ACT-0001", complete, `{"label":"unknown"}`); w.Code != http.StatusNotFound {
		t.Errorf("/api/v1/actor/feedback [complete] : HTTP %d, attendu 404", w.Code)
	}
	if apres, _ := s.ledger.Count(); apres != avant {
		t.Errorf("le ledger a changé : %d → %d", avant, apres)
	}
}

func TestVue_RacineValeurInattendueVautVueReduite(t *testing.T) {
	// Seule « complete », exactement et une seule fois, ouvre la vue complète.
	s, preuve := serveurPeuple(t)
	for _, v := range []string{"", "Complete", "COMPLETE", "complète", "completes", "complete, complete", "reduite", "1", "true"} {
		w := appel(t, s, http.MethodGet, "/actors", ptr(v), "")
		sansDonneeInterne(t, "/actors ["+v+"]", w.Body.Bytes())
		w = appel(t, s, http.MethodGet, "/evidence/"+preuve, ptr(v), "")
		if w.Code != http.StatusNotFound {
			t.Errorf("/evidence [%q] : HTTP %d, attendu 404", v, w.Code)
		}
	}
	// En double, même avec la bonne valeur : vue réduite.
	req := httptest.NewRequest(http.MethodGet, "/actors", nil)
	req.Header.Add(enteteVue, valeurComplete)
	req.Header.Add(enteteVue, valeurComplete)
	w := httptest.NewRecorder()
	s.apiMux().ServeHTTP(w, req)
	sansDonneeInterne(t, "/actors [complete ×2]", w.Body.Bytes())
}

func TestVue_RacineCompleteInchangee(t *testing.T) {
	s, preuve := serveurPeuple(t)
	// /actors : les cibles sont là, comme avant.
	var acts []map[string]any
	_ = json.Unmarshal(appel(t, s, http.MethodGet, "/actors", complete, "").Body.Bytes(), &acts)
	if len(acts) == 0 {
		t.Fatal("/actors : aucun acteur dans la vue complète")
	}
	vues := map[string]bool{}
	for _, a := range acts {
		ts, ok := a["targets"].([]any)
		if !ok {
			t.Fatal("/actors : champ targets absent de la vue complète")
		}
		for _, x := range ts {
			vues[x.(string)] = true
		}
		if _, ok := a["tl"]; !ok {
			t.Error("/actors : champ tl absent de la vue complète")
		}
		if _, ok := a["nb_cibles"]; ok {
			t.Error("/actors : champ nb_cibles ajouté à la vue complète")
		}
	}
	for _, c := range ciblesEssai {
		if !vues[c] {
			t.Errorf("/actors : cible %q absente de la vue complète", c)
		}
	}
	// /campaigns : cibles et signature calculée sur les noms, comme avant.
	var camps []map[string]any
	_ = json.Unmarshal(appel(t, s, http.MethodGet, "/campaigns", complete, "").Body.Bytes(), &camps)
	if len(camps) == 0 {
		t.Fatal("/campaigns : aucune campagne")
	}
	for _, c := range camps {
		cs, ok := c["cibles"].([]any)
		if !ok || len(cs) == 0 {
			t.Errorf("/campaigns : cibles absentes de la vue complète : %v", c)
		}
		if _, ok := c["nb_cibles"]; ok {
			t.Error("/campaigns : champ nb_cibles ajouté à la vue complète")
		}
	}
	// /evidence : la preuve reste lisible.
	if w := appel(t, s, http.MethodGet, "/evidence/"+preuve, complete, ""); w.Code != http.StatusOK {
		t.Errorf("/evidence : HTTP %d, attendu 200", w.Code)
	}
	// /feedback : consigné, comme avant.
	avant, _ := s.ledger.Count()
	if w := appel(t, s, http.MethodPost, "/feedback/ACT-0001", complete, `{"label":"unknown"}`); w.Code != http.StatusOK {
		t.Fatalf("feedback : HTTP %d, attendu 200", w.Code)
	}
	if apres, _ := s.ledger.Count(); apres != avant+1 {
		t.Errorf("feedback non consigné : %d → %d", avant, apres)
	}
}

func TestVue_EnteteEnMinusculesSurLeSocket(t *testing.T) {
	// Par le socket réel, avec l'en-tête écrit en minuscules comme le relaient
	// nginx ou l'agrégateur : la casse du NOM ne change rien, l'arbre si.
	s, preuve := serveurPeuple(t)
	sock := filepath.Join(t.TempDir(), "actor.sock")
	go func() { _ = s.serveAPI(sock) }()
	brut := func(chemin, entetes string) (int, []byte) {
		t.Helper()
		var conn net.Conn
		var err error
		for i := 0; i < 100; i++ {
			if conn, err = net.Dial("unix", sock); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("connexion au socket d'API : %v", err)
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "GET "+chemin+" HTTP/1.1\r\nHost: actor\r\n"+entetes+"Connection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	// Racine + « complete » en minuscules : vue complète, preuve lisible.
	code, corps := brut("/actors", "x-sbx-vue: complete\r\n")
	if code != http.StatusOK || !bytes.Contains(corps, []byte(`"targets"`)) {
		t.Errorf("socket /actors [complete] : HTTP %d, vue complète attendue", code)
	}
	if code, _ := brut("/evidence/"+preuve, "x-sbx-vue: complete\r\n"); code != http.StatusOK {
		t.Errorf("socket /evidence [complete] : HTTP %d, attendu 200", code)
	}
	// Racine sans en-tête : vue réduite.
	code, corps = brut("/actors", "")
	if code != http.StatusOK {
		t.Fatalf("socket /actors : HTTP %d", code)
	}
	sansDonneeInterne(t, "socket /actors [sans en-tête]", corps)
	// Arbre préfixé, même avec « complete » : vue réduite, pas de preuve.
	code, corps = brut("/api/v1/actor/actors", "x-sbx-vue: complete\r\n")
	if code != http.StatusOK {
		t.Fatalf("socket /api/v1/actor/actors : HTTP %d", code)
	}
	sansDonneeInterne(t, "socket /api/v1/actor/actors [complete]", corps)
	if code, _ := brut("/api/v1/actor/evidence/"+preuve, "x-sbx-vue: complete\r\n"); code != http.StatusNotFound {
		t.Errorf("socket /api/v1/actor/evidence [complete] : HTTP %d, attendu 404", code)
	}
}
