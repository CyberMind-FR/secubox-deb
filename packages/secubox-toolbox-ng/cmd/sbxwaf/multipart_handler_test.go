// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Câblage de la capture multipart dans le gestionnaire (#3257, tâche 4), le
// journal (mode, signaux, gravité « audit ») et le correctif du chemin texte
// (spécification A2). Les serveurs sont montés comme dans main_test.go : un
// &Server{...} direct, un backend httptest, l'adresse cliente dans RemoteAddr.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Corpus PROPRE à ces tests (le corpus livré arrive à la tâche 5) : sqli en
// blocage, php2shell en detect avec la signature progress + fichiers.
const corpusMultipartTest = `{
  "_meta": {"version": "t"},
  "categories": {
    "sqli": {"name": "S", "severity": "critical", "patterns": [{"id": "sq-1", "pattern": "union select"}]},
    "php2shell": {"name": "P", "severity": "high", "mode": "detect",
      "patterns": [{"id": "p-1", "pattern": "zzzjamais"}],
      "structural": [
        {"id": "php2shell-001", "check": "upload_progress_fichiers", "params": {"fichiers_apres_min": 2},
         "cve": "CVE-2026-109619"}
      ]}
  }
}`

const profilsPHPTest = `{
	"services": {"nextcloud": {"legit_paths": []}},
	"vhosts": {"nc.example": "nextcloud"},
	"php_services": ["nextcloud"]
}`

const ipPublique = "203.0.113.7"

type bancMultipart struct {
	s       *Server
	journal string
	fx      *fauxNft

	mu      sync.Mutex
	shaRecu [32]byte
	nRecu   int64
	appels  int
}

// nouveauBancMultipart monte un Server complet : règles, vhost PHP, journal,
// compteurs de ban et ban nft branché sur un faux exécutant (aucun nft réel).
// backend nil : un backend qui lit tout le corps et en garde l'empreinte.
func nouveauBancMultipart(t *testing.T, backend http.HandlerFunc) *bancMultipart {
	t.Helper()
	b := &bancMultipart{journal: filepath.Join(t.TempDir(), "menaces.jsonl"), fx: &fauxNft{}}
	if backend == nil {
		backend = func(w http.ResponseWriter, r *http.Request) {
			h := sha256.New()
			n, _ := io.Copy(h, r.Body)
			b.mu.Lock()
			copy(b.shaRecu[:], h.Sum(nil))
			b.nRecu = n
			b.appels++
			b.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}
	}
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	h, p, err := splitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	vp, err := chargerVhostProfilesDepuis([]byte(profilsPHPTest))
	if err != nil {
		t.Fatal(err)
	}
	b.s = &Server{
		routeLookup:   func(string) (string, int, bool) { return h, p, true },
		rules:         LoadRules(ecrisRegles(t, corpusMultipartTest)),
		ban:           NewBan(300*time.Second, 3),
		escalateBan:   NewBan(time.Hour, 3),
		threatLog:     NewThreatLog(b.journal),
		nftBan:        banneurTest(t, b.fx),
		vhostProfiles: vp,
	}
	return b
}

func (b *bancMultipart) envoyer(host, chemin, ip, ct string, corps io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://"+host+chemin, corps)
	req.Host = host
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	b.s.handler().ServeHTTP(rec, req)
	return rec
}

// verifierRecu : le backend a reçu exactement les octets envoyés.
func (b *bancMultipart) verifierRecu(t *testing.T, corps []byte) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.appels != 1 || b.nRecu != int64(len(corps)) || b.shaRecu != sha256.Sum256(corps) {
		t.Fatalf("backend : %d appel(s), %d octets reçus sur %d, empreinte identique=%v",
			b.appels, b.nRecu, len(corps), b.shaRecu == sha256.Sum256(corps))
	}
}

func (b *bancMultipart) lignes(t *testing.T) []map[string]any {
	t.Helper()
	brut, err := os.ReadFile(b.journal)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(brut)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("ligne illisible %q : %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func lignesDe(ls []map[string]any, prefixeCategorie string) []map[string]any {
	var out []map[string]any
	for _, l := range ls {
		if c, _ := l["category"].(string); strings.HasPrefix(c, prefixeCategorie) {
			out = append(out, l)
		}
	}
	return out
}

func signalLigne(t *testing.T, l map[string]any, cle string) int {
	t.Helper()
	s, ok := l["signals"].(map[string]any)
	if !ok {
		t.Fatalf("ligne sans signals : %v", l)
	}
	v, ok := s[cle].(float64)
	if !ok {
		t.Fatalf("signals.%s absent : %v", cle, s)
	}
	return int(v)
}

// verifierSansSanction : ni compteur de ban, ni escalade, ni commande nft, ni
// enregistrement de ban. appliquerBan part en goroutine : on laisse le temps.
func (b *bancMultipart) verifierSansSanction(t *testing.T, ip string) {
	t.Helper()
	if n := b.s.ban.Count(ip); n != 0 {
		t.Errorf("compteur de ban = %d, attendu 0", n)
	}
	if n := b.s.escalateBan.Count(ip); n != 0 {
		t.Errorf("compteur d'escalade = %d, attendu 0", n)
	}
	time.Sleep(100 * time.Millisecond)
	b.fx.mu.Lock()
	cmds := len(b.fx.cmds)
	b.fx.mu.Unlock()
	if cmds != 0 {
		t.Errorf("%d commande(s) nft exécutée(s), attendu aucune", cmds)
	}
	for _, rec := range b.s.nftBan.store.ActiveBans(time.Now().Unix()) {
		if rec.IP == ip {
			t.Errorf("enregistrement de ban pour %s : %+v", ip, rec)
		}
	}
}

// corpsExploit : progress puis deux fichiers (CVE-2026-109619). Les valeurs,
// noms de fichier et contenus sont des marqueurs : ils ne doivent JAMAIS
// apparaître dans le journal.
func corpsExploit() []byte {
	return corpsMultipart("BND", []partieTest{
		{nom: nomProgressPHP, contenu: "VALEUR-SECRETE"},
		{nom: "f1", filename: "charge-secrete.php", fichier: true, contenu: "CONTENU-SECRET"},
		{nom: "f2", filename: "b.txt", fichier: true, contenu: "y"},
	}, false)
}

func contenuTexte(n int) string {
	return strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ", n/26+1)[:n]
}

func TestMultipartPHPDetecteProgressSansBloquer(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	b.s.capturesMultipart = make(chan struct{}, 1)
	corps := corpsExploit()

	rec := b.envoyer("nc.example", "/index.php/apps/files/ajax/upload.php", ipPublique, ctTest, bytes.NewReader(corps))

	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu la réponse 200 du backend : detect ne bloque jamais", rec.Code)
	}
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	if len(ls) != 1 {
		t.Fatalf("%d ligne(s) au journal, attendu 1 : %v", len(ls), ls)
	}
	l := ls[0]
	for cle, want := range map[string]string{
		"category": "php2shell", "rule_id": "php2shell-001", "action": "detect",
		"mode": "detect", "severity": "high", "client_ip": ipPublique, "host": "nc.example",
	} {
		if got, _ := l[cle].(string); got != want {
			t.Errorf("%s = %q, attendu %q", cle, got, want)
		}
	}
	if p := signalLigne(t, l, "parties"); p != 3 {
		t.Errorf("signals.parties = %d, attendu 3", p)
	}
	if f := signalLigne(t, l, "fichiers_apres_progress"); f != 2 {
		t.Errorf("signals.fichiers_apres_progress = %d, attendu 2", f)
	}
	brut, _ := os.ReadFile(b.journal)
	for _, secret := range []string{"VALEUR-SECRETE", "charge-secrete", "CONTENU-SECRET"} {
		if strings.Contains(string(brut), secret) {
			t.Errorf("le journal contient %q : ni valeur, ni nom de fichier, ni contenu", secret)
		}
	}
	if n := len(b.s.capturesMultipart); n != 0 {
		t.Errorf("jeton de capture non rendu (%d pris)", n)
	}
	b.verifierSansSanction(t, ipPublique)
}

func TestMultipartNonPHPPasAnalyse(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	corps := corpsExploit()
	rec := b.envoyer("autre.example", "/upload", ipPublique, ctTest, bytes.NewReader(corps))
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	if n := len(lignesDe(ls, "php2shell")) + len(lignesDe(ls, "multipart-")); n != 0 {
		t.Fatalf("vhost non PHP : aucune ligne php2shell ni multipart-* attendue, eu %v", ls)
	}
}

// R12 : le réseau local n'est plus exempté ; voir TestCaptureLANAnalyseeEnLocal
// (capture_cablage_test.go), qui remplace TestMultipartLANExempte.

// PHP analyse le corps AVANT d'exécuter le script : les contournements de
// l'inspection regex (ncBypass, chemin « statique », hôte de confiance) ne
// valent pas pour la capture (spécification § 8, point 3).
func TestMultipartNcBypassAnalyse(t *testing.T) {
	cas := []struct {
		nom, chemin string
		confiance   bool
	}{
		{"ncBypass", "/index.php/login/v2/", false},
		{"chemin statique", "/status.php", false},
		{"hote de confiance", "/upload", true},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			b := nouveauBancMultipart(t, nil)
			if c.confiance {
				b.s.trustedHosts = map[string]struct{}{"nc.example": {}}
			}
			corps := corpsExploit()
			rec := b.envoyer("nc.example", c.chemin, ipPublique, ctTest, bytes.NewReader(corps))
			if rec.Code != http.StatusOK {
				t.Fatalf("statut %d, attendu 200", rec.Code)
			}
			b.verifierRecu(t, corps)
			if ls := lignesDe(b.lignes(t), "php2shell"); len(ls) != 1 {
				t.Fatalf("une ligne php2shell attendue, eu %v", b.lignes(t))
			}
		})
	}
}

func TestMultipartGrosEnvoiTronque(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	corps := corpsMultipart("BND", []partieTest{
		{nom: "f", filename: "gros.bin", fichier: true, contenu: contenuTexte(3 << 20)},
	}, false)
	rec := b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corps))
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	if len(lignesDe(ls, "php2shell")) != 0 {
		t.Fatalf("aucune ligne php2shell attendue : %v", ls)
	}
	tr := lignesDe(ls, "multipart-")
	if len(ls) != 1 || len(tr) != 1 {
		t.Fatalf("une seule ligne multipart-tronque attendue, eu %v", ls)
	}
	l := tr[0]
	if l["category"] != "multipart-tronque" || l["action"] != "multipart-tronque" || l["severity"] != "audit" {
		t.Errorf("ligne inattendue : %v", l)
	}
	if _, ok := l["mode"]; ok {
		t.Errorf("une ligne d'état ne porte pas de mode : %v", l)
	}
	if p := signalLigne(t, l, "parties"); p != 1 {
		t.Errorf("signals.parties = %d, attendu 1", p)
	}
}

// Le backend refuse sans lire : le Transport peut encore lire le corps quand
// le gestionnaire fige la capture. Aucune panique, aucun blocage, aucune course
// (-race). Le second fichier est hors de la fenêtre : jamais de php2shell.
// Statut : 413 si la réponse précède l'erreur d'écriture, 502 sinon (le
// backend ferme la connexion sans lire plus de 256 Kio) — les deux sont admis.
func TestMultipartBackendNeLitPas(t *testing.T) {
	b := nouveauBancMultipart(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	})
	b.s.capturesMultipart = make(chan struct{}, 1)
	corps := corpsMultipart("BND", []partieTest{
		{nom: nomProgressPHP, contenu: "x"},
		{nom: "f1", filename: "a", fichier: true, contenu: contenuTexte(3 << 20)},
		{nom: "f2", filename: "b", fichier: true, contenu: "y"},
	}, false)

	fini := make(chan int, 1)
	go func() {
		fini <- b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corps)).Code
	}()
	select {
	case code := <-fini:
		t.Logf("statut %d ; journal : %v", code, b.lignes(t))
		if code != http.StatusRequestEntityTooLarge && code != http.StatusBadGateway {
			t.Errorf("statut %d, attendu 413 (réponse du backend) ou 502", code)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("le gestionnaire ne rend pas la main")
	}
	if ls := lignesDe(b.lignes(t), "php2shell"); len(ls) != 0 {
		t.Fatalf("aucune ligne php2shell attendue, eu %v", ls)
	}
	if n := len(b.s.capturesMultipart); n != 0 {
		t.Errorf("jeton de capture non rendu (%d pris)", n)
	}
	b.verifierSansSanction(t, ipPublique)
}

func TestMultipartConcurrenceLimite(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	b.s.capturesMultipart = make(chan struct{}, 1)
	b.s.capturesMultipart <- struct{}{} // une autre capture est en cours
	corps := corpsExploit()

	rec := b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corps))
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	if len(ls) != 1 {
		t.Fatalf("une seule ligne multipart-concurrence attendue, eu %v", ls)
	}
	l := ls[0]
	// Ruling R10 : le sémaphore plein a sa propre catégorie ; multipart-limite
	// reste réservé au plafond de parties de l'analyseur.
	if l["category"] != "multipart-concurrence" || l["action"] != "multipart-concurrence" || l["severity"] != "audit" {
		t.Errorf("ligne inattendue : %v", l)
	}
	if c := signalLigne(t, l, "concurrence"); c != 1 {
		t.Errorf("signals.concurrence = %d, attendu la capacité réelle 1", c)
	}
	if n := len(b.s.capturesMultipart); n != 1 {
		t.Errorf("le jeton de l'autre capture a été touché (%d pris, attendu 1)", n)
	}
	b.verifierSansSanction(t, ipPublique)
}

// Le multipart reste « binaire » pour les regex : le corps n'atteint jamais
// MatchDetail, même capturé. Témoin : le même texte en urlencoded est bloqué.
func TestMultipartRegexInchangee(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	corps := corpsMultipart("BND", []partieTest{{nom: "q", contenu: "x union select 1,2 x"}}, false)
	if rec := b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corps)); rec.Code == http.StatusForbidden {
		t.Fatal("multipart sur vhost PHP : 403, le corps a été passé aux regex")
	}
	b.verifierRecu(t, corps)
	temoin := b.envoyer("nc.example", "/upload", "203.0.113.8", "application/x-www-form-urlencoded",
		strings.NewReader("q=x union select 1,2 x"))
	if temoin.Code != http.StatusForbidden {
		t.Fatalf("témoin urlencoded : statut %d, attendu 403 (la règle doit être active)", temoin.Code)
	}
}

// « multipart/form-data, … » : multipart pour PHP (coupure à la virgule), texte
// pour corpsBinaire (coupure au point-virgule seulement). Le chemin texte lit
// alors la fenêtre AU TRAVERS de la capture, puis le proxy lit le reste : chaque
// octet passe une seule fois par la capture, l'analyse voit le corps entier, et
// le backend reçoit tout.
func TestMultipartContentTypeVirguleLuParLeCheminTexte(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	corps := corpsExploit()
	rec := b.envoyer("nc.example", "/upload", ipPublique, "multipart/form-data, boundary=BND", bytes.NewReader(corps))
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	if len(ls) != 1 || len(lignesDe(ls, "php2shell")) != 1 {
		t.Fatalf("une seule ligne php2shell attendue, eu %v", ls)
	}
	if p := signalLigne(t, ls[0], "parties"); p != 3 {
		t.Errorf("signals.parties = %d, attendu 3 : la capture a vu des octets en double ou manquants", p)
	}
}

// Un corps BLOQUÉ n'a jamais atteint le backend : il ne doit pas être analysé.
// Avec la virgule, le chemin texte lit la fenêtre au travers de la capture
// (lus > 0), puis la règle sqli bloque : la sortie 403 ne doit produire aucune
// ligne php2shell (gravité high vers actord pour un corps jamais relayé).
func TestMultipartBloqueNonRelayePasAnalyse(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	b.s.capturesMultipart = make(chan struct{}, 1)
	corps := corpsMultipart("BND", []partieTest{
		{nom: nomProgressPHP, contenu: "x union select 1,2 x"},
		{nom: "f1", filename: "a", fichier: true, contenu: "y"},
		{nom: "f2", filename: "b", fichier: true, contenu: "z"},
	}, false)

	rec := b.envoyer("nc.example", "/upload", ipPublique, "multipart/form-data, boundary=BND", bytes.NewReader(corps))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("statut %d, attendu 403 (règle sqli bloquante)", rec.Code)
	}
	b.mu.Lock()
	appels := b.appels
	b.mu.Unlock()
	if appels != 0 {
		t.Fatalf("%d appel(s) au backend, attendu 0", appels)
	}
	ls := b.lignes(t)
	if n := len(lignesDe(ls, "php2shell")) + len(lignesDe(ls, "multipart-")); n != 0 {
		t.Fatalf("corps jamais relayé : aucune ligne php2shell ni multipart-* attendue, eu %v", ls)
	}
	if len(lignesDe(ls, "sqli")) != 1 {
		t.Errorf("la ligne du blocage sqli manque : %v", ls)
	}
	if n := len(b.s.capturesMultipart); n != 0 {
		t.Errorf("jeton de capture non rendu (%d pris)", n)
	}
}

// Le second site de relais : un GET passe par le cache média, et un défaut
// (miss) relaie par proxy.ServeHTTP(cw, r). relaye doit y être posé aussi.
func TestMultipartCacheMediaMissAnalyse(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	b.s.mediaCache = NewMediaCache(t.TempDir())
	corps := corpsExploit()
	req := httptest.NewRequest(http.MethodGet, "http://nc.example/upload", bytes.NewReader(corps))
	req.Host = "nc.example"
	req.RemoteAddr = ipPublique + ":40000"
	req.Header.Set("Content-Type", ctTest)
	rec := httptest.NewRecorder()
	b.s.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Header().Get("X-SecuBox-Cache") != "miss" {
		t.Fatalf("statut %d, cache %q : attendu 200 par le chemin miss du cache média", rec.Code, rec.Header().Get("X-SecuBox-Cache"))
	}
	b.verifierRecu(t, corps)
	if ls := lignesDe(b.lignes(t), "php2shell"); len(ls) != 1 {
		t.Fatalf("une ligne php2shell attendue, eu %v", b.lignes(t))
	}
}

func TestSevToIntAudit(t *testing.T) {
	for sev, want := range map[string]int{"audit": 10, "critical": 90, "high": 75, "medium": 50, "low": 25, "inconnu": 40, "": 40} {
		if got := sevToInt(sev); got != want {
			t.Errorf("sevToInt(%q) = %d, attendu %d", sev, got, want)
		}
	}
}

func TestThreatLogModeEtSignaux(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "menaces.jsonl")
	tl := NewThreatLog(chemin)
	tl.Record(ThreatRecord{ClientIP: ipPublique, Category: "php2shell", Severity: "high", Action: "detect",
		Mode: "detect", Signaux: map[string]int{"parties": 3}})
	tl.Record(ThreatRecord{ClientIP: ipPublique, Category: "sqli", Severity: "critical", Action: "warning"})

	brut, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	ls := strings.Split(strings.TrimSpace(string(brut)), "\n")
	if len(ls) != 2 {
		t.Fatalf("2 lignes attendues, eu %q", brut)
	}
	var avec, sans map[string]any
	if err := json.Unmarshal([]byte(ls[0]), &avec); err != nil {
		t.Fatalf("ligne 1 illisible : %v", err)
	}
	if err := json.Unmarshal([]byte(ls[1]), &sans); err != nil {
		t.Fatalf("ligne 2 illisible : %v", err)
	}
	if avec["mode"] != "detect" {
		t.Errorf("mode = %v, attendu detect", avec["mode"])
	}
	if s, _ := avec["signals"].(map[string]any); s["parties"] != float64(3) {
		t.Errorf("signals = %v, attendu parties 3", avec["signals"])
	}
	for _, cle := range []string{"mode", "signals"} {
		if _, ok := sans[cle]; ok {
			t.Errorf("une ligne sans %s ne doit pas porter la clé : %s", cle, ls[1])
		}
	}
}

// ─── Chemin texte : correctif A2 (lecture fenêtre + 1, erreur journalisée) ──

// corpsJSON rend un corps JSON d'exactement n octets, sans motif d'attaque.
func corpsJSON(n int) []byte {
	const debut, fin = `{"d":"`, `"}`
	return []byte(debut + contenuTexte(n-len(debut)-len(fin)) + fin)
}

func lignesTronque(ls []map[string]any) int {
	return len(lignesDe(ls, "body-inspect-truncated"))
}

func TestCorpsTexteExactementFenetrePasTronque(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	corps := corpsJSON(defaultMaxBodyInspect)
	if rec := b.envoyer("app.example", "/api", ipPublique, "application/json", bytes.NewReader(corps)); rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	b.verifierRecu(t, corps)
	if n := lignesTronque(b.lignes(t)); n != 0 {
		t.Fatalf("corps d'exactement la fenêtre déclaré tronqué (%d ligne(s))", n)
	}
}

func TestCorpsTexteFenetrePlusUnTronque(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	corps := corpsJSON(defaultMaxBodyInspect + 1)
	if rec := b.envoyer("app.example", "/api", ipPublique, "application/json", bytes.NewReader(corps)); rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	b.verifierRecu(t, corps)
	if n := lignesTronque(b.lignes(t)); n != 1 {
		t.Fatalf("%d ligne(s) body-inspect-truncated, attendu 1", n)
	}
}

// MatchDetail ne reçoit que la fenêtre, pas l'octet de plus lu pour savoir
// s'il y a une suite : un motif qui ne se complète qu'avec cet octet ne
// déclenche pas, et le backend reçoit tout.
func TestCorpsTexteMatchDetailBorneALaFenetre(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	const motif = "union select"
	corps := []byte(contenuTexte(defaultMaxBodyInspect+1-len(motif)) + motif + "BBBB")
	if rec := b.envoyer("app.example", "/api", ipPublique, "text/plain", bytes.NewReader(corps)); rec.Code == http.StatusForbidden {
		t.Fatal("403 : MatchDetail a reçu plus que la fenêtre")
	}
	b.verifierRecu(t, corps)
}

func TestCorpsTexteErreurLectureJournalisee(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	coupe := io.MultiReader(strings.NewReader("0123456789"), iotestErr{})
	b.envoyer("app.example", "/api", ipPublique, "application/json", coupe)
	if n := lignesTronque(b.lignes(t)); n != 1 {
		t.Fatalf("lecture en erreur après 10 octets : %d ligne(s) body-inspect-truncated, attendu 1", n)
	}
}

// Sonde P3 de la relecture finale (I1), au niveau du gestionnaire : frontières
// suivantes précédées d'un LF nu. mime/multipart n'y voyait qu'une partie et
// rien n'était journalisé ; PHP, lui, lit l'exploit (rfc1867.c, find_boundary).
func TestMultipartSondeP3LFNuJournalisee(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	corps := []byte(corpsSondeP3())
	if rec := b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corps)); rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	b.verifierRecu(t, corps)
	ls := lignesDe(b.lignes(t), "php2shell")
	if len(ls) != 1 || ls[0]["rule_id"] != "php2shell-001" {
		t.Fatalf("une ligne php2shell-001 attendue, eu %v", b.lignes(t))
	}
	if f := signalLigne(t, ls[0], "fichiers_apres_progress"); f != 60 {
		t.Errorf("signals.fichiers_apres_progress = %d, attendu 60", f)
	}
}
