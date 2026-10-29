// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Tests du socle de #3273 (tâche 2) : service PHP d'un hôte, entrée PHP de la
// requête, choix du corps à capturer, signatures filtrées par service, et
// câblage de la capture urlencoded dans le gestionnaire.
package main

import (
	"bytes"
	"crypto/sha256"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestServicePHP(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"nextcloud": {"legit_paths": []}, "roundcube": {"legit_paths": []}},
		"vhosts": {"nc.example": "nextcloud"},
		"php_services": ["nextcloud", "roundcube"],
		"php_hotes": ["^webmail\\."]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	cas := []struct {
		hote    string
		service string
		php     bool
	}{
		{"NC.example:443", "nextcloud", true},
		{"webmail.autre", "", true},
		{"x.example", "", false},
	}
	for _, c := range cas {
		if s, p := vp.servicePHP(c.hote); s != c.service || p != c.php {
			t.Errorf("servicePHP(%q) = (%q, %v), attendu (%q, %v)", c.hote, s, p, c.service, c.php)
		}
	}
	if s, p := (*VhostProfiles)(nil).servicePHP("x"); s != "" || p {
		t.Errorf("récepteur nil : (%q, %v), attendu (\"\", false)", s, p)
	}
}

func TestEstUrlencodedPHP(t *testing.T) {
	cas := map[string]bool{
		"application/x-www-form-urlencoded":                true,
		"Application/X-WWW-Form-Urlencoded; charset=UTF-8": true,
		"application/x-www-form-urlencodedX":               false,
		"multipart/form-data; boundary=x":                  false,
		"":                                                 false,
	}
	for ct, attendu := range cas {
		if got := estUrlencodedPHP(ct); got != attendu {
			t.Errorf("estUrlencodedPHP(%q) = %v, attendu %v", ct, got, attendu)
		}
	}
}

func TestNouvelleEntreePHP(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "http://webmail.example/?_task=mail&.from=x", nil)
	e := s.nouvelleEntreePHP(r, "roundcube")
	if e.Service != "roundcube" || e.Methode != "GET" || e.Chemin != "/" {
		t.Errorf("entrée : %+v", e)
	}
	// I2 : la requête est gardée brute avant le relais, lue après la réponse.
	if e.requeteBrute != "_task=mail&.from=x" || e.Requete.Variables != 0 {
		t.Errorf("avant le relais : requeteBrute=%q Variables=%d, attendu brute et non lue", e.requeteBrute, e.Requete.Variables)
	}
	e.lireRequete()
	if v := e.Requete.Valeurs("_from"); len(v) != 1 || v[0] != "x" {
		t.Errorf("Requete.Valeurs(_from) = %v, attendu [x]", v)
	}
	if e.Corps != nil || e.Multipart != nil {
		t.Errorf("sans corps : Corps=%v Multipart=%v, attendu nil", e.Corps, e.Multipart)
	}
}

func TestCorpsACapturer(t *testing.T) {
	s := &Server{}
	cas := []struct {
		nom     string
		methode string
		ct      string
		corps   io.Reader
		genre   genreCorps
		plafond int
		jeton   bool
	}{
		{"multipart", http.MethodPost, ctTest, bytes.NewReader(corpsExploit()), corpsMultipart, s.fenetreCapture(), true},
		{"urlencoded", http.MethodPost, "application/x-www-form-urlencoded", strings.NewReader("a=b"), corpsUrlencoded, s.fenetreCapture(), true},
		{"GET sans corps", http.MethodGet, "", nil, corpsAucun, 0, false},
		{"JSON", http.MethodPost, "application/json", strings.NewReader(`{"a":1}`), corpsAucun, 0, false},
	}
	for _, c := range cas {
		r := httptest.NewRequest(c.methode, "http://nc.example/", c.corps)
		if c.ct != "" {
			r.Header.Set("Content-Type", c.ct)
		}
		e := s.nouvelleEntreePHP(r, "nextcloud")
		g, p, j := s.corpsACapturer(r, e, indicateursTous)
		if g != c.genre || p != c.plafond || j != c.jeton {
			t.Errorf("%s : (%v, %d, %v), attendu (%v, %d, %v)", c.nom, g, p, j, c.genre, c.plafond, c.jeton)
		}
	}
}

func TestCompleterCorpsUrlencoded(t *testing.T) {
	e := &EntreePHP{}
	completerCorps(e, corpsUrlencoded, []byte("_uid=1&_uid=2&a=b"), "application/x-www-form-urlencoded", true)
	if e.Corps == nil {
		t.Fatal("Corps nil après completerCorps urlencoded")
	}
	if e.Corps.Variables != 3 {
		t.Errorf("Variables = %d, attendu 3", e.Corps.Variables)
	}
	if v := e.Corps.Valeurs("_uid"); len(v) != 2 || v[0] != "1" || v[1] != "2" {
		t.Errorf("Valeurs(_uid) = %v, attendu [1 2]", v)
	}
	if e.Multipart != nil {
		t.Error("urlencoded : Multipart doit rester nil")
	}
}

func TestCompleterCorpsMultipart(t *testing.T) {
	e := &EntreePHP{}
	completerCorps(e, corpsMultipart, corpsExploit(), ctTest, true)
	if e.Multipart == nil {
		t.Fatal("Multipart nil après completerCorps multipart")
	}
	// corpsExploit compte trois parties (progress, f1, f2), comme le relève
	// déjà TestMultipartPHPDetecteProgressSansBloquer ; le brief disait 4.
	if e.Multipart.Parties != 3 || !e.Multipart.Progress {
		t.Errorf("Parties=%d Progress=%v, attendu 3 et true", e.Multipart.Parties, e.Multipart.Progress)
	}
	if e.Corps != nil {
		t.Error("multipart : Corps doit rester nil")
	}
}

func TestEvaluerPHPFiltreServices(t *testing.T) {
	r := LoadRules(ecrisRegles(t, `{"categories": {"php2shell": {"severity": "high", "mode": "detect",
	  "structural": [{"id": "rc-1", "check": "filename_charge", "services": ["roundcube"]}]}}}`))
	if _, c, rej, _ := r.Integrite(); c != 1 || len(rej) != 0 {
		t.Fatalf("charges=%d rejetes=%v, attendu 1 et aucun rejet", c, rej)
	}
	cas := map[string]int{"nextcloud": 0, "roundcube": 1, "": 1}
	for service, attendu := range cas {
		e := &EntreePHP{Service: service, Multipart: &ResultatMultipart{FilenamePHP: true}}
		if got := r.EvaluerPHP(e); len(got) != attendu {
			t.Errorf("service %q : %d détection(s) %v, attendu %d", service, len(got), got, attendu)
		}
	}
	// Sans multipart, un contrôle multipart ne déclenche jamais.
	if got := r.EvaluerPHP(&EntreePHP{Service: "roundcube"}); len(got) != 0 {
		t.Errorf("sans multipart : %v, attendu aucune", got)
	}
}

func TestStructurelServicesMalTypeRejete(t *testing.T) {
	r := LoadRules(ecrisRegles(t, `{"categories": {"php2shell": {"mode": "detect",
	  "structural": [{"id": "rc-chaine", "check": "filename_charge", "services": "roundcube"},
	                 {"id": "ok", "check": "filename_charge", "services": ["roundcube"]}]}}}`))
	_, c, rej, _ := r.Integrite()
	if c != 1 || len(rej) != 1 || !strings.Contains(rej[0], "rc-chaine") {
		t.Errorf("charges=%d rejetes=%v, attendu 1 et le rejet nommé rc-chaine", c, rej)
	}
}

// bancJeton : banc multipart dont le backend relève aussi le nombre de jetons
// pris PENDANT le relais, dans les deux sémaphores (multipart + urlencoded).
// Capacités : 1 chacun.
func bancJeton(t *testing.T) (*bancMultipart, *[2]int) {
	t.Helper()
	var b *bancMultipart
	var mu sync.Mutex
	pris := [2]int{-1, -1}
	b = nouveauBancMultipart(t, func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		b.mu.Lock()
		copy(b.shaRecu[:], h.Sum(nil))
		b.nRecu = n
		b.appels++
		b.mu.Unlock()
		mu.Lock()
		pris = [2]int{len(b.s.capturesMultipart), len(b.s.capturesUrlencoded)}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	b.s.capturesMultipart = make(chan struct{}, 1)
	b.s.capturesUrlencoded = make(chan struct{}, 1)
	return b, &pris
}

// corpusUrlencodedTest : le corpus multipart plus un contrôle qui lit le corps
// urlencoded (variables_nombre, seuil jamais atteint). Sans lui, aucun
// contrôle actif ne lit l'urlencoded, qui n'est donc pas capturé (passe
// finale M4).
const corpusUrlencodedTest = `{"categories": {
  "php2shell": {"name": "P", "severity": "high", "mode": "detect", "structural": [
    {"id": "php2shell-001", "check": "upload_progress_fichiers", "params": {"fichiers_apres_min": 2}}]},
  "php_requete": {"name": "Q", "severity": "medium", "mode": "detect", "structural": [
    {"id": "php-006", "check": "variables_nombre", "params": {"variables_min": 1000000}}]}
}}`

func TestRequetePHPUrlencodedRelayeIntact(t *testing.T) {
	b, pris := bancJeton(t)
	b.s.rules = LoadRules(ecrisRegles(t, corpusUrlencodedTest))
	corps := []byte("_task=mail&_action=send&_message=" + contenuTexte(2<<20))
	for i := 0; i < 2; i++ {
		b.mu.Lock()
		b.appels = 0
		b.mu.Unlock()
		rec := b.envoyer("nc.example", "/index.php", ipPublique, "application/x-www-form-urlencoded", bytes.NewReader(corps))
		if rec.Code != http.StatusOK {
			t.Fatalf("envoi %d : statut %d, attendu 200", i, rec.Code)
		}
		b.verifierRecu(t, corps)
		if *pris != [2]int{0, 1} {
			t.Errorf("envoi %d : jetons pris pendant le relais (multipart, urlencoded) = %v, attendu [0 1]", i, *pris)
		}
		if n, u := len(b.s.capturesMultipart), len(b.s.capturesUrlencoded); n+u != 0 {
			t.Fatalf("envoi %d : jeton non rendu (%d multipart, %d urlencoded)", i, n, u)
		}
	}
	if ls := lignesDe(b.lignes(t), "capture-concurrence"); len(ls) != 0 {
		t.Errorf("lignes capture-concurrence inattendues : %v", ls)
	}
	b.verifierSansSanction(t, ipPublique)
}

func TestRequetePHPJetonRenduSansCorps(t *testing.T) {
	b, pris := bancJeton(t)
	req := httptest.NewRequest(http.MethodGet, "http://nc.example/index.php?_task=mail", nil)
	req.Host = "nc.example"
	req.RemoteAddr = ipPublique + ":40000"
	rec := httptest.NewRecorder()
	b.s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	if *pris != [2]int{0, 0} {
		t.Errorf("jetons pris pendant le relais d'un GET : %v, attendu [0 0]", *pris)
	}
	if n, u := len(b.s.capturesMultipart), len(b.s.capturesUrlencoded); n+u != 0 {
		t.Errorf("jeton pris après un GET (%d multipart, %d urlencoded)", n, u)
	}
	if ls := b.lignes(t); len(ls) != 0 {
		t.Errorf("aucune ligne attendue, eu %v", ls)
	}
}

// compterCrochets remplace les crochets d'étiquette d'outil et de lecture de
// la requête par des compteurs, rétablis en fin de test.
func compterCrochets(t *testing.T) (outil, requete *atomic.Int64) {
	t.Helper()
	outil, requete = new(atomic.Int64), new(atomic.Int64)
	o, q := etiquetteOutilPHP, lireRequetePHP
	etiquetteOutilPHP = func(ua, chemin string) string { outil.Add(1); return o(ua, chemin) }
	lireRequetePHP = func(brut string) ParametresPHP { requete.Add(1); return q(brut) }
	t.Cleanup(func() { etiquetteOutilPHP, lireRequetePHP = o, q })
	return outil, requete
}

// I2 : un GET de vhost PHP sans corps ni ligne ne calcule ni l'étiquette
// d'outil (21 regex) ni la lecture de la requête : aucune signature chargée
// ne lit la requête, et aucune ligne n'est écrite.
func TestRequetePHPGetSansLigneParesseux(t *testing.T) {
	outil, requete := compterCrochets(t)
	b, _ := bancJeton(t)
	req := httptest.NewRequest(http.MethodGet, "http://nc.example/index.php?_task=mail&_from=x", nil)
	req.Host = "nc.example"
	req.RemoteAddr = ipPublique + ":40000"
	req.Header.Set("User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")
	rec := httptest.NewRecorder()
	b.s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	if ls := lignesDe(b.lignes(t), ""); len(ls) != 0 {
		t.Fatalf("aucune ligne attendue, eu %v", ls)
	}
	if n := outil.Load(); n != 0 {
		t.Errorf("étiquetteOutil appelée %d fois, attendu 0", n)
	}
	if n := requete.Load(); n != 0 {
		t.Errorf("requête lue %d fois, attendu 0", n)
	}
}

// I2 : quand une signature chargée lit la requête, la lecture a lieu, une
// fois, dans l'analyse (après la réponse).
func TestRequetePHPRequeteLueApresSiUtile(t *testing.T) {
	parametreRequis["test_requete"] = ""
	controlesRequete["test_requete"] = true
	t.Cleanup(func() { delete(parametreRequis, "test_requete"); delete(controlesRequete, "test_requete") })
	_, requete := compterCrochets(t)
	b, _ := bancJeton(t)
	b.s.rules = LoadRules(ecrisRegles(t, `{"categories": {"t": {"mode": "detect",
	  "structural": [{"id": "t-1", "check": "test_requete"}]}}}`))
	req := httptest.NewRequest(http.MethodGet, "http://nc.example/index.php?_task=mail", nil)
	req.Host = "nc.example"
	req.RemoteAddr = ipPublique + ":40000"
	b.s.handler().ServeHTTP(httptest.NewRecorder(), req)
	if n := requete.Load(); n != 1 {
		t.Errorf("requête lue %d fois, attendu 1", n)
	}
}

// R-W7 : l'urlencoded a son propre sémaphore de 8 jetons. Saturé, il écrit une
// ligne capture-concurrence de genre urlencoded, et un envoi PHP2Shell est
// toujours capturé et détecté sur le sémaphore multipart.
func TestCaptureUrlencodedSatureeMultipartCapture(t *testing.T) {
	if capturesUrlencodedMax != 8 || capturesMultipartMax != 16 {
		t.Fatalf("capacités %d/%d, attendu 8 (urlencoded) et 16 (multipart)", capturesUrlencodedMax, capturesMultipartMax)
	}
	b := nouveauBancMultipart(t, nil)
	b.s.rules = LoadRules(ecrisRegles(t, corpusUrlencodedTest))
	b.s.capturesMultipart = make(chan struct{}, capturesMultipartMax)
	b.s.capturesUrlencoded = make(chan struct{}, capturesUrlencodedMax)
	for i := 0; i < capturesUrlencodedMax; i++ {
		b.s.capturesUrlencoded <- struct{}{} // huit envois urlencoded en cours
	}
	corpsU := []byte("_task=mail&_action=send")
	b.envoyer("nc.example", "/index.php", ipPublique, "application/x-www-form-urlencoded", bytes.NewReader(corpsU))
	b.verifierRecu(t, corpsU)
	b.mu.Lock()
	b.appels = 0
	b.mu.Unlock()
	corps := corpsExploit()
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corps))
	b.verifierRecu(t, corps)

	ls := b.lignes(t)
	conc := lignesDe(ls, "capture-concurrence")
	if len(conc) != 1 {
		t.Fatalf("une ligne capture-concurrence attendue, eu %v", ls)
	}
	if g := signalLigne(t, conc[0], "genre"); g != int(corpsUrlencoded) {
		t.Errorf("signals.genre = %d, attendu %d (urlencoded)", g, corpsUrlencoded)
	}
	if c := signalLigne(t, conc[0], "concurrence"); c != capturesUrlencodedMax {
		t.Errorf("signals.concurrence = %d, attendu %d", c, capturesUrlencodedMax)
	}
	if d := lignesDe(ls, "php2shell"); len(d) != 1 {
		t.Errorf("le multipart PHP2Shell n'a pas été capturé : %v", ls)
	}
	if n, u := len(b.s.capturesMultipart), len(b.s.capturesUrlencoded); n != 0 || u != capturesUrlencodedMax {
		t.Errorf("jetons après coup : %d multipart, %d urlencoded ; attendu 0 et %d (ceux des autres)", n, u, capturesUrlencodedMax)
	}
	b.verifierSansSanction(t, ipPublique)
}

// R-W8 M1 : un service inconnu dans "services" n'empêche pas le chargement
// mais est signalé (journal et Integrite) ; "" et un doublon rejettent la
// signature, nommément.
func TestStructurelServicesInconnuAverti(t *testing.T) {
	var sortie bytes.Buffer
	log.SetOutput(&sortie)
	defer log.SetOutput(os.Stderr)
	r := LoadRules(ecrisRegles(t, `{"categories": {"php2shell": {"mode": "detect",
	  "structural": [{"id": "s-1", "check": "filename_charge", "services": ["nextcloud", "fantome"]}]}}}`))
	_, c, rej, avertis := r.Integrite()
	if c != 1 || len(rej) != 0 {
		t.Errorf("charges=%d rejetes=%v, attendu 1 et aucun rejet", c, rej)
	}
	if len(avertis) != 1 || !strings.Contains(avertis[0], "s-1") || !strings.Contains(avertis[0], "fantome") {
		t.Errorf("avertis=%v, attendu un avertissement nommant s-1 et fantome", avertis)
	}
	if !strings.Contains(sortie.String(), "fantome") {
		t.Errorf("aucun avertissement au chargement : %q", sortie.String())
	}
}

func TestStructurelServicesVideOuDoublonRejete(t *testing.T) {
	r := LoadRules(ecrisRegles(t, `{"categories": {"php2shell": {"mode": "detect",
	  "structural": [{"id": "vide", "check": "filename_charge", "services": [""]},
	                 {"id": "doublon", "check": "filename_charge", "services": ["roundcube", "roundcube"]},
	                 {"id": "ok", "check": "filename_charge", "services": ["roundcube", "nextcloud"]}]}}}`))
	_, c, rej, avertis := r.Integrite()
	j := strings.Join(rej, "|")
	if c != 1 || len(rej) != 2 || !strings.Contains(j, "php2shell/vide") || !strings.Contains(j, "php2shell/doublon") {
		t.Errorf("charges=%d rejetes=%v, attendu 1 chargée et vide, doublon rejetées", c, rej)
	}
	if len(avertis) != 0 {
		t.Errorf("avertis=%v, attendu aucun", avertis)
	}
}

// R-W8 M2 : un corps urlencoded coupé par la fenêtre est dit tronqué.
func TestCompleterCorpsUrlencodedTronque(t *testing.T) {
	for _, complet := range []bool{true, false} {
		e := &EntreePHP{}
		completerCorps(e, corpsUrlencoded, []byte("_uid=1&a=b"), "application/x-www-form-urlencoded", complet)
		if e.Corps == nil || e.Corps.Tronque == complet {
			t.Errorf("complet=%v : Corps=%+v, attendu Tronque=%v", complet, e.Corps, !complet)
		}
	}
	if p := lireParametresPHP("a=b"); p.Tronque {
		t.Error("lireParametresPHP seule ne dit jamais tronqué")
	}
}
