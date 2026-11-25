// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// t36 : un début d'heure et de jour UTC, plus une demi-heure.
const t36 = int64(1_788_048_000) + 14*3600 + 1800

func horloge(t testing.TB, now int64) *int64 {
	t.Helper()
	ancien := maintenant
	h := now
	maintenant = func() int64 { return h }
	t.Cleanup(func() { maintenant = ancien })
	return &h
}

func evt(ts int64, ip, cible, action string) *envelope.Envelope {
	return &envelope.Envelope{EventID: envelope.NewEventID(), Timestamp: ts, Sensor: envelope.SensorWAF, SrcIP: ip,
		DstService: cible, Action: action, Severity: 70, PathShape: "/p-" + ip, RuleID: "sqli-001", UserAgentFamily: "curl", CredentialTokenHash: "cred-essai", GeoCountry: "US"}
}

func val(p *uint32) int {
	if p == nil {
		return -1
	}
	return int(*p)
}

func seul(t *testing.T, s *Server) *graph.Actor {
	t.Helper()
	l := s.graph.Actors()
	if len(l) != 1 {
		t.Fatalf("%d acteurs, attendu 1", len(l))
	}
	return l[0]
}

func TestActiviteNullAvantLaCouvertureZeroApres(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	s.observe(evt(t36-5*3600, "203.0.113.1", "a.exemple.test", envelope.ActionObserve)) // ouvre la couverture, en milieu d'heure
	s.observe(evt(t36-60, "203.0.113.1", "a.exemple.test", envelope.ActionBlock))
	s.observe(evt(t36-30, "203.0.113.1", "a.exemple.test", envelope.ActionBlock))
	a := seul(t, s)
	x := s.act.acteurs[a.ID]
	h := s.act.serie(3600, 24, t36, x.heureEvts)
	if len(h.Valeurs) != 24 || h.Debut+23*3600 != t36-1800 {
		t.Fatalf("série %+v", h)
	}
	for i := 0; i < 18; i++ {
		if h.Valeurs[i] != nil {
			t.Fatalf("heure %d non couverte : attendu null, obtenu %d", i, *h.Valeurs[i])
		}
	}
	if val(h.Valeurs[18]) != 1 || len(h.Partielles) != 1 || h.Partielles[0] != 18 {
		t.Errorf("première heure : %d, partielles %v", val(h.Valeurs[18]), h.Partielles)
	}
	for i := 19; i < 23; i++ {
		if val(h.Valeurs[i]) != 0 {
			t.Errorf("heure %d couverte et vide : attendu 0, obtenu %d", i, val(h.Valeurs[i]))
		}
	}
	if val(h.Valeurs[23]) != 2 {
		t.Errorf("heure en cours : %d", val(h.Valeurs[23]))
	}
	j := s.act.serie(86400, joursGardes, t36, x.jourEvts)
	if val(j.Valeurs[14]) != 3 || j.Valeurs[13] != nil || len(j.Partielles) != 1 {
		t.Errorf("jours %d / partielles %v", val(j.Valeurs[14]), j.Partielles)
	}
	if x.dernierBan != t36-30 {
		t.Errorf("dernier ban %d", x.dernierBan)
	}
	if te := s.act.tendance(x, t36); te.Bans != nil || te.Adresses != nil {
		t.Error("tendance annoncée sans 48 h couvertes")
	}
}

func TestActiviteAnneauxEtHorlogeAbsurde(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.observe(evt(t36, "203.0.113.1", "a.exemple.test", envelope.ActionObserve))
	s.observe(evt(t36+10*86400, "203.0.113.1", "a.exemple.test", envelope.ActionObserve)) // dans le futur : pas compté
	a := seul(t, s)
	x := s.act.acteurs[a.ID]
	if x.heure != t36/3600 {
		t.Fatal("un événement du futur a déplacé l'anneau")
	}
	*now = t36 + 3*86400
	s.observe(evt(*now, "203.0.113.1", "a.exemple.test", envelope.ActionObserve))
	if n := val(s.act.serie(3600, 24, *now, x.heureEvts).Valeurs[23]); n != 1 {
		t.Errorf("après trois jours, heure en cours = %d", n)
	}
	total := uint32(0)
	for r := x.heure - heuresGardees + 1; r <= x.heure; r++ {
		total += x.heureEvts(r)
	}
	if total != 1 {
		t.Errorf("anneau horaire non vidé : %d", total)
	}
	s.observe(evt(*now-60*86400, "203.0.113.1", "a.exemple.test", envelope.ActionObserve)) // trop ancien pour les anneaux
	if j := s.act.serie(86400, joursGardes, *now, x.jourEvts); val(j.Valeurs[11]) != 1 || val(j.Valeurs[14]) != 1 || val(j.Valeurs[13]) != 0 {
		t.Errorf("jours : %d %d %d", val(j.Valeurs[11]), val(j.Valeurs[13]), val(j.Valeurs[14]))
	}
}

func TestActiviteTendanceSurDeuxFenetresPleines(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	s.observe(evt(t36-80*3600, "203.0.113.1", "a.exemple.test", envelope.ActionObserve))
	for i := 0; i < 3; i++ {
		s.observe(evt(t36-30*3600+int64(i), "203.0.113.1", "a.exemple.test", envelope.ActionBlock))
	}
	for i := 0; i < 5; i++ {
		s.observe(evt(t36-2*3600+int64(i), "203.0.113.1", "a.exemple.test", envelope.ActionBlock))
	}
	a := seul(t, s)
	te := s.act.tendance(s.act.acteurs[a.ID], t36)
	if te.Bans == nil || *te.Bans != (paireTendance{5, 3}) {
		t.Errorf("bans %+v", te.Bans)
	}
	if te.Adresses == nil || *te.Adresses != (paireTendance{0, 0}) {
		t.Errorf("adresses %+v : 0 nouvelle est une mesure", te.Adresses)
	}
	// Sans mise en route suffisante, « nouvelle adresse » ne veut rien dire.
	s.act.depuisGraphe = t36 - 60*3600
	if te = s.act.tendance(s.act.acteurs[a.ID], t36); te.Adresses != nil || te.Bans == nil {
		t.Error("adresses nouvelles annoncées trop tôt")
	}
	// Un trou au milieu : plus de tendance.
	s.act.trous = [][2]int64{{t36 - 40*3600, t36 - 38*3600}}
	if te = s.act.tendance(s.act.acteurs[a.ID], t36); te.Bans != nil {
		t.Error("tendance annoncée à travers un trou")
	}
	h := s.act.serie(3600, heuresGardees, t36, s.act.acteurs[a.ID].heureEvts)
	if h.Valeurs[10] != nil { // heure entièrement dans le trou
		t.Errorf("heure dans un trou : %d", *h.Valeurs[10])
	}
}

func TestActiviteSuitLesFusions(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	inex := map[string]bool{"x1.exemple.test": true, "x2.exemple.test": true}
	for i, ip := range []string{"203.0.113.1", "198.51.100.1"} {
		for _, c := range []string{"x1.exemple.test", "x2.exemple.test"} {
			e := evt(t36-3600+int64(i)*3600, ip, c, envelope.ActionBlock)
			e.CredentialTokenHash, e.UserAgentFamily = "", ""
			e.PathShape, e.GeoCountry = fmt.Sprintf("/%d", i), []string{"US", "GB"}[i]
			s.observe(e)
		}
	}
	if s.graph.Len() != 2 {
		t.Fatalf("précondition : %d acteurs", s.graph.Len())
	}
	if s.graph.Consolider(inex) == 0 {
		t.Fatal("précondition : aucune fusion")
	}
	s.act.suivreFusions(s.graph)
	a := seul(t, s)
	x := s.act.acteurs[a.ID]
	h := s.act.serie(3600, 24, t36, x.heureEvts)
	if len(s.act.acteurs) != 1 || val(h.Valeurs[23]) != 2 || val(h.Valeurs[22]) != 2 || x.premier != t36-3600 {
		t.Errorf("fusion : %d entrées, %d/%d, premier %d", len(s.act.acteurs), val(h.Valeurs[22]), val(h.Valeurs[23]), x.premier)
	}
	if x.nIPs != 2 {
		t.Error("la fusion compterait des adresses nouvelles")
	}
	s.purgerMemoire(t36 + 10)
	if len(s.act.acteurs) != 0 {
		t.Error("compteurs gardés après purge")
	}
}

func TestActivitePlafondDacteurs(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	s.act.acteurs = make(map[string]*activiteActeur, activiteMax)
	for i := 0; i < activiteMax; i++ {
		s.act.acteurs[fmt.Sprintf("X-%d", i)] = &activiteActeur{}
	}
	s.observe(evt(t36, "203.0.113.1", "a.exemple.test", envelope.ActionObserve))
	a := seul(t, s)
	if s.act.acteurs[a.ID] != nil || len(s.act.acteurs) != activiteMax {
		t.Error("plafond dépassé")
	}
	if d := s.calculerDetail(a.ID, true); d == nil || d.Heures != nil || d.Tendance != nil || d.DernierBan != nil {
		t.Error("une série inventée pour un acteur non suivi")
	}
}

func TestActiviteTechniquesBorneesSansAdresse(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	for i := 0; i < 60; i++ {
		e := evt(t36, "203.0.113.1", "a.exemple.test", envelope.ActionObserve)
		e.RuleID = fmt.Sprintf("regle-%02d", i)
		s.observe(e)
	}
	for _, r := range []string{"vers 198.51.100.4", "compte admin@exemple.test", "2001:db8:0:1::4", strings.Repeat("é", 200)} {
		e := evt(t36, "203.0.113.1", "a.exemple.test", envelope.ActionObserve)
		e.RuleID = r
		s.observe(e)
	}
	x := s.act.acteurs[seul(t, s).ID]
	if len(x.tech) > techParActeur+1 {
		t.Errorf("%d techniques retenues", len(x.tech))
	}
	tout := strings.Join(s.act.noms, "|")
	for _, interdit := range []string{"198.51", "@", "2001:db8", strings.Repeat("é", techNomMax+1)} {
		if strings.Contains(tout, interdit) {
			t.Errorf("nom retenu : %q", interdit)
		}
	}
	if l := s.act.techniques(x); len(l) != techDetail {
		t.Errorf("%d techniques servies", len(l))
	}
}

// ── Instantané ──────────────────────────────────────────────────────────────────────────────────

func TestInstantaneReprendLesSeriesSansDoubleCompte(t *testing.T) {
	now := horloge(t, t36)
	dir := t.TempDir()
	s := serveur(t)
	s.actChemin, s.rebuildMax = filepath.Join(dir, "activite.json"), 3
	envoyer := func(s *Server, e *envelope.Envelope) {
		if err := s.store.Ingest(e); err != nil {
			t.Fatal(err)
		}
		s.observe(e)
	}
	s.rebuild() // magasin vide : couverture à partir de maintenant
	debut := *now
	for i := 0; i < 6; i++ { // un événement par jour
		*now = debut + int64(i)*86400
		envoyer(s, evt(*now, "203.0.113.1", "a.exemple.test", envelope.ActionBlock))
	}
	s.sauverActivite()
	if fi, err := os.Stat(s.actChemin); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("instantané : %v %v", fi, err)
	}
	*now += 60
	envoyer(s, evt(*now, "203.0.113.1", "a.exemple.test", envelope.ActionObserve)) // après l'instantané

	r := serveur(t)
	r.store, r.actChemin, r.rebuildMax = s.store, s.actChemin, 3
	*now += 60
	r.rebuild()
	a := seul(t, r)
	x := r.act.acteurs[a.ID]
	j := r.act.serie(86400, joursGardes, *now, x.jourEvts)
	got := []int{}
	for _, p := range j.Valeurs[8:] {
		got = append(got, val(p))
	}
	if fmt.Sprint(got) != "[-1 1 1 1 1 1 2]" {
		t.Errorf("jours après reprise : %v", got)
	}
	if r.act.depuis != debut || r.premierVu(a) != debut || a.FirstSeen == debut {
		t.Errorf("depuis %d premier %d (graphe %d), attendu %d", r.act.depuis, r.premierVu(a), a.FirstSeen, debut)
	}
	if len(r.act.trous) != 0 {
		t.Errorf("un redémarrage ordinaire compté comme trou : %v", r.act.trous)
	}
	if x.modules[indexModule(envelope.SensorWAF)] != 7 || r.act.techniques(x)[0].N != 7 {
		t.Errorf("modules %v", x.modules)
	}
	// Le graphe reconstruit est celui d'un démarrage SANS instantané.
	sans := serveur(t)
	sans.store, sans.rebuildMax = s.store, 3
	sans.rebuild()
	b1, _ := json.Marshal(r.graph.Actors())
	b2, _ := json.Marshal(sans.graph.Actors())
	if string(b1) != string(b2) {
		t.Error("l'instantané a changé le graphe")
	}
}

func TestInstantaneEcarteOuIllisible(t *testing.T) {
	now := horloge(t, t36)
	s := serveur(t)
	s.actChemin, s.rebuildMax = filepath.Join(t.TempDir(), "activite.json"), 2
	s.rebuild()
	s.observe(evt(*now, "203.0.113.1", "a.exemple.test", envelope.ActionObserve))
	s.sauverActivite()
	// L'instantané s'arrête avant le plus ancien événement rejoué : lacune inconnue, écarté.
	*now += 3 * 86400
	for i := int64(0); i < 2; i++ {
		_ = s.store.Ingest(evt(*now-7200+i, "203.0.113.1", "a.exemple.test", envelope.ActionObserve))
	}
	r := serveur(t)
	r.store, r.actChemin, r.rebuildMax = s.store, s.actChemin, 2
	r.rebuild()
	if r.act.depuis != *now-7200 {
		t.Errorf("couverture %d, attendu celle du rejeu", r.act.depuis)
	}
	if len(r.act.trous) != 1 || r.act.trous[0][1] != *now { // deux heures sans rien avant le démarrage
		t.Errorf("trous %v", r.act.trous)
	}
	for _, mauvais := range []string{"{", `{"version":9}`, `{"version":1,"depuis":5,"genere_le":1}`, ""} {
		if err := os.WriteFile(r.actChemin, []byte(mauvais), 0o600); err != nil {
			t.Fatal(err)
		}
		if lireInstantane(r.actChemin, *now) != nil {
			t.Errorf("instantané %q accepté", mauvais)
		}
	}
	r.actChemin = filepath.Join(t.TempDir(), "absent", "x.json")
	r.sauverActivite() // écriture impossible : journalisée, sans panique
}

// ── Routes ──────────────────────────────────────────────────────────────────────────────────────

func TestDetailVueReduiteSansDonneeInterne(t *testing.T) {
	s, _ := serveurPeuple(t)
	id := seul(t, s).ID
	for _, p := range prefixes {
		for _, v := range variantesReduites(p) {
			nom := nomVariante(p+"/actors/{id}", v)
			w := appel(t, s, http.MethodGet, p+"/actors/"+id, v, "")
			sansDonneeInterne(t, nom, w.Body.Bytes())
			var o struct {
				ID       string         `json:"id"`
				Premier  int64          `json:"premier"`
				Dernier  int64          `json:"dernier"`
				First    string         `json:"first"`
				Targets  *[]string      `json:"targets"`
				NbCibles int            `json:"nb_cibles"`
				Detail   map[string]any `json:"detail"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
				t.Fatal(err)
			}
			sansCle(t, nom, o.Detail)
			if o.ID != id || o.Premier == 0 || o.Dernier < o.Premier || o.First == "" || o.Targets != nil || o.NbCibles != 2 {
				t.Errorf("%s : fiche %+v", nom, o)
			}
			// Liste blanche figée : un champ nouveau se décide ici.
			attendus := "campagnes couverture_depuis dernier_ban evenements genere_le heures jours mesure modules pays premier_borne reseaux techniques tendance"
			if got := clesTriees(o.Detail); got != attendus {
				t.Errorf("%s : clés %q", nom, got)
			}
			c := o.Detail["campagnes"].([]any)
			if len(c) != 1 || c[0].(map[string]any)["signature"] == s.campagnes()[0].Signature {
				t.Errorf("%s : campagne %v (signature opaque attendue)", nom, c)
			}
			if c[0].(map[string]any)["signature"] != s.signatureOpaque(s.campagnes()[0].Signature) {
				t.Errorf("%s : la signature ne mène pas à l'onglet campagnes", nom)
			}
			sansDonneeInterne(t, p+"/activite", appel(t, s, http.MethodGet, p+"/activite?ids="+id, v, "").Body.Bytes())
		}
	}
	// Vue complète : la même chose, plus ce que webActor portait déjà ; signature en clair.
	w := appel(t, s, http.MethodGet, "/actors/"+id, complete, "")
	if !strings.Contains(w.Body.String(), `"targets":["192.0.2.10:443"`) || !strings.Contains(w.Body.String(), s.campagnes()[0].Signature) {
		t.Errorf("vue complète : %s", w.Body.String())
	}
}

func clesTriees(m map[string]any) string {
	n := map[string]int{}
	for k := range m {
		n[k] = 1
	}
	return strings.Join(premiers(n, 100), " ")
}

func TestDetailPaysEtReseauxSansASNDansLeGraphe(t *testing.T) {
	s := serveurRotation(t)
	a := s.graph.Actors()[0]
	d := s.calculerDetail(a.ID, true)
	if d.Reseaux == nil || d.Reseaux.Examinees != len(a.IPs) || d.Reseaux.Classes["proxy_loue"] == 0 {
		t.Fatalf("réseaux %+v", d.Reseaux)
	}
	if d.Pays == nil || d.Pays.Top[0].Code != "US" || d.Pays.Adresses != len(a.IPs) {
		t.Errorf("pays %+v", d.Pays)
	}
	if len(a.ASNs) != 0 {
		t.Error("l'ASN est entré dans le graphe")
	}
	// Ni base ni catalogue ni fiche : rien de mesuré, jamais « 100 % inconnu ».
	nu := serveur(t)
	horloge(t, t36)
	e := evt(t36, "203.0.113.1", "a.exemple.test", envelope.ActionObserve)
	e.GeoCountry = ""
	nu.observe(e)
	if d := nu.calculerDetail(seul(t, nu).ID, true); d.Reseaux != nil || d.Pays != nil {
		t.Errorf("réseaux %+v pays %+v", d.Reseaux, d.Pays)
	}
}

func TestDetailNeToucheNiGrapheNiMagasin(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	for _, e := range fluxAvecASN(t36, true) {
		s.observe(e)
	}
	avant, _ := json.Marshal(s.graph.Actors())
	_ = s.store.Close() // toute lecture du magasin échouerait
	for _, a := range s.graph.Actors() {
		if w := appel(t, s, http.MethodGet, "/actors/"+a.ID, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"heures":{`) {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	}
	apres, _ := json.Marshal(s.graph.Actors())
	if string(avant) != string(apres) {
		t.Error("une lecture a changé le graphe")
	}
}

func TestDetailBorneEnConcurrenceEtGarde(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	s.observe(evt(t36, "203.0.113.1", "a.exemple.test", envelope.ActionObserve))
	id := seul(t, s).ID
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); appel(t, s, http.MethodGet, "/actors/"+id, nil, "") }()
		go func() {
			defer wg.Done()
			s.observe(evt(t36+int64(i), "203.0.113.1", "a.exemple.test", envelope.ActionObserve))
			appel(t, s, http.MethodGet, "/activite?ids="+id, nil, "")
		}()
	}
	wg.Wait()
	if g := s.detailT.vals["r:"+id]; g.d == nil || s.detail(id, true, nil) != g.d {
		t.Error("le détail gardé n'est pas resservi")
	}
	// Places prises : la fiche de base est servie, le détail vaut null.
	s.detailT.vals = nil
	for i := 0; i < detailPlaces; i++ {
		s.detailT.places <- struct{}{}
	}
	w := appel(t, s, http.MethodGet, "/actors/"+id, nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"detail":null`) || !strings.Contains(w.Body.String(), `"priority"`) {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
}

func TestActiviteParLot(t *testing.T) {
	horloge(t, t36)
	s := serveur(t)
	s.observe(evt(t36, "203.0.113.1", "a.exemple.test", envelope.ActionBlock))
	robot := evt(t36, "203.0.113.9", "a.exemple.test", envelope.ActionObserve)
	robot.RuleID, robot.Severity, robot.BehaviorTags, robot.UserAgentFamily = "", 10, []string{"robots"}, "googlebot"
	s.observe(robot)
	id := seul(t, s).ID
	var o lotActivite
	w := appel(t, s, http.MethodGet, "/activite?ids="+id+",ACT-9999", nil, "")
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if len(o.Acteurs) != 1 || len(o.Acteurs[id]) != 24 || val(o.Acteurs[id][23]) != 1 || o.Acteurs[id][0] != nil {
		t.Errorf("acteurs %v", w.Body.String())
	}
	if val(o.Evenements[23]) != 2 || val(o.Bloques[23]) != 1 {
		t.Errorf("ensemble : %d / %d (robots connus compris, comme /stats)", val(o.Evenements[23]), val(o.Bloques[23]))
	}
	if w := appel(t, s, http.MethodGet, "/activite", nil, ""); w.Code != 200 {
		t.Errorf("sans ids : %d", w.Code)
	}
	trop := strings.Repeat("A,", 60) + "A"
	for _, q := range []string{trop, "a/b", "A,", strings.Repeat("x", 40), "%3Cimg%3E"} {
		if w := appel(t, s, http.MethodGet, "/activite?ids="+q, nil, ""); w.Code != http.StatusBadRequest {
			t.Errorf("ids=%.20q : %d", q, w.Code)
		}
	}
	if w := appel(t, s, http.MethodPost, "/activite?ids="+id, nil, ""); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST : %d", w.Code)
	}
}

// ── Coût ────────────────────────────────────────────────────────────────────────────────────────

// serveurCharge : n acteurs d'une adresse, plus un acteur de `gros` adresses.
func serveurCharge(tb testing.TB, n, gros int) (*Server, string) {
	tb.Helper()
	horloge(tb, t36)
	s := &Server{graph: graph.New(0), accum: map[string]*actorSignals{}}
	for i := 0; i < n; i++ {
		e := evt(t36-int64(i%86400), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "", envelope.ActionObserve)
		e.GeoCountry, e.CredentialTokenHash, e.UserAgentFamily, e.RuleID = "", "", "", fmt.Sprintf("r%d", i%40)
		s.observe(e)
	}
	x := &activiteActeur{premier: t36 - 86400}
	s.act.acteurs["GROS"] = x
	id := s.graph.Actors()[0].ID
	a, _ := s.graph.Get(id)
	for i := 0; i < gros; i++ {
		ip := fmt.Sprintf("198.18.%d.%d", i>>8&255, i&255)
		a.IPs = append(a.IPs, ip)
		s.sources[ip] = &ficheSource{dernier: t36, asn: uint32(64496 + i%200), pays: [2]byte{'U', 'S'}}
	}
	return s, id
}

func TestActiviteMemoireEtPoidsDesListes(t *testing.T) {
	s, _ := serveurCharge(t, 3658, 0)
	if n := len(s.act.acteurs); n != 3659 {
		t.Fatalf("%d entrées", n)
	}
	var m0, m1 runtime.MemStats
	garde := make([]*activiteActeur, 0, 3658)
	runtime.GC()
	runtime.ReadMemStats(&m0)
	for i := 0; i < 3658; i++ {
		garde = append(garde, &activiteActeur{tech: make([]techniqueN, 3)})
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	runtime.KeepAlive(garde)
	if ko := (int64(m1.HeapAlloc) - int64(m0.HeapAlloc)) / 1024; ko > 5000 {
		t.Errorf("%d Ko pour 3658 acteurs", ko)
	} else {
		t.Logf("compteurs : %d Ko pour %d acteurs", ko, len(garde))
	}
	// Le corps de /actors ne gagne que les deux dates : moins de 30 %.
	w := appel(t, s, http.MethodGet, "/actors", nil, "")
	ajout := 0
	for _, a := range s.graph.Actors() {
		ajout += len(fmt.Sprintf(`"premier":%d,"dernier":%d,`, a.FirstSeen, a.LastSeen))
	}
	if avant := w.Body.Len() - ajout; ajout*100 > 30*avant {
		t.Errorf("/actors : +%d octets sur %d", ajout, avant)
	} else {
		t.Logf("/actors : %d octets, dont %d (%d %%) pour les dates", w.Body.Len(), ajout, ajout*100/avant)
	}
	ids := []string{}
	for _, a := range s.graph.Actors()[:activiteIDs] {
		ids = append(ids, a.ID)
	}
	w = appel(t, s, http.MethodGet, "/activite?ids="+strings.Join(ids, ","), nil, "")
	if w.Body.Len() > 12000 {
		t.Errorf("/activite : %d octets pour 60 lignes", w.Body.Len())
	} else {
		t.Logf("/activite : %d octets pour 60 lignes", w.Body.Len())
	}
}

func BenchmarkDetail2454Adresses(b *testing.B) {
	s, id := serveurCharge(b, 3658, 2454)
	_, _ = s.campDetT.lire(campDetTTL, s.campagnesParActeur)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.calculerDetail(id, true)
	}
}

func BenchmarkNoter(b *testing.B) {
	s, id := serveurCharge(b, 3658, 0)
	a, _ := s.graph.Get(id)
	e := evt(t36, "203.0.113.1", "a.exemple.test", envelope.ActionBlock)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.act.noterGlobal(e)
		s.act.noter(a, e)
	}
}

func BenchmarkInstantane(b *testing.B) {
	s, _ := serveurCharge(b, 3658, 0)
	s.actChemin = filepath.Join(b.TempDir(), "a.json")
	for i := 0; i < b.N; i++ {
		s.sauverActivite()
	}
}
