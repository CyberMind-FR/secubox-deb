// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — tests des signatures PHP génériques (#3273, R-PHP1 à R-PHP4)
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"
)

// Corpus PROPRE à ces tests : la catégorie php_requete, en detect, sans service.
const corpusPHPGeneriqueTest = `{"_meta": {"version": "t"}, "categories": {"php_requete": {"name": "P", "severity": "medium", "mode": "detect",
  "patterns": [{"id": "php-p", "pattern": "zzzjamais"}],
  "structural": [
   {"id": "php-001", "check": "parties_nombre", "params": {"parties_min": 1021}, "severity": "high", "cve": "CVE-2023-0662"},
   {"id": "php-002", "check": "xml_dtd_prologue", "severity": "high", "cve": "CVE-2023-3823"},
   {"id": "php-003", "check": "cookie_prefixe_normalise", "severity": "medium", "cve": "CVE-2024-2756"},
   {"id": "php-004", "check": "frontiere_longueur", "params": {"longueur_min": 71}, "severity": "medium", "cve": "CVE-2024-8925"},
   {"id": "php-005", "check": "frontiere_longueur", "params": {"longueur_min": 5121}, "severity": "high", "cve": "CVE-2024-8925"}
  ]}}}`

// pocDTD : la PoC du GHSA-3qrf-m4j2-pcrr (spécification § 3.7).
const pocDTD = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "https://x/"> %remote; %intern; %trick;]><d:propfind xmlns:d="DAV:"/>`

func TestEstXMLPHP(t *testing.T) {
	cas := []struct {
		methode, ct string
		want        bool
	}{
		{"PROPFIND", "", true},
		{"propfind", "", true},
		{"POST", "text/xml; charset=utf-8", true},
		{"POST", "application/xml", true},
		{"POST", "application/json", false},
		{"GET", "", false},
	}
	for _, c := range cas {
		if got := estXMLPHP(c.methode, c.ct); got != c.want {
			t.Errorf("estXMLPHP(%q, %q) = %v, attendu %v", c.methode, c.ct, got, c.want)
		}
	}
}

// utf16Avec encode s en UTF-16 avec BOM (little-endian ou big-endian).
func utf16Avec(s string, le bool) []byte {
	out := []byte{0xFF, 0xFE}
	if !le {
		out = []byte{0xFE, 0xFF}
	}
	for _, u := range utf16.Encode([]rune(s)) {
		if le {
			out = append(out, byte(u), byte(u>>8))
		} else {
			out = append(out, byte(u>>8), byte(u))
		}
	}
	return out
}

func TestPrologueAvecDTD(t *testing.T) {
	cas := []struct {
		nom   string
		debut []byte
		want  bool
	}{
		{"PoC", []byte(pocDTD), true},
		{"sans DTD", []byte(`<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop/></d:propfind>`), false},
		{"après la racine", []byte(`<d:propfind/><!DOCTYPE x>`), false},
		{"commentaire puis doctype", []byte(" \n<!-- c --><!doctype x><r/>"), true},
		{"doctype dans un commentaire", []byte(`<!-- <!DOCTYPE x> --><r/>`), false},
		{"racine factice dans un commentaire", []byte(`<!-- <a --><!DOCTYPE x><r/>`), true},
		{"racine factice dans une PI", []byte(`<?p <a ?><!DOCTYPE x><r/>`), true},
		{"commentaire non fermé", []byte(`<!-- <!DOCTYPE x>`), false},
		{"commentaires imbriqués", []byte(`<!-- <!-- --> <!DOCTYPE x>`), true},
		{"PI non terminée", []byte(`<?p <!DOCTYPE x>`), false},
		{"entity seule", []byte(`<?xml version="1.0"?><!entity a "b"><r/>`), true},
		{"UTF-16LE", utf16Avec(pocDTD, true), true},
		{"UTF-16BE", utf16Avec(pocDTD, false), true},
		{"UTF-16 sans DTD", utf16Avec(`<?xml version="1.0"?><r/>`, true), false},
		{"vide", nil, false},
		{"BOM seul", []byte{0xFF, 0xFE}, false},
	}
	for _, c := range cas {
		if got := prologueAvecDTD(c.debut); got != c.want {
			t.Errorf("%s : prologueAvecDTD = %v, attendu %v", c.nom, got, c.want)
		}
	}
}

func TestCookieFauxPrefixe(t *testing.T) {
	cas := []struct {
		lignes []string
		want   bool
	}{
		{[]string{"_[Host-x=y"}, true},
		{[]string{"__Host-nc_sameSiteCookiestrict=true"}, false},
		{[]string{"a=1", " .[Secure-z=1"}, true},
		{[]string{"__Host-x=1; _.Host-y=2"}, true},
		{[]string{"x=1"}, false},
		{nil, false},
	}
	for _, c := range cas {
		if got := cookieFauxPrefixe(c.lignes); got != c.want {
			t.Errorf("cookieFauxPrefixe(%q) = %v, attendu %v", c.lignes, got, c.want)
		}
	}
}

// corpsDeuxParties : deux parties texte sous la frontière donnée.
func corpsDeuxParties(frontiere string) []byte {
	return fabriquerMultipart(frontiere, []partieTest{{nom: "a", contenu: "1"}, {nom: "b", contenu: "2"}}, false)
}

func TestAnalyserMultipartLongueurFrontiere(t *testing.T) {
	cas := []struct {
		n       int
		statut  StatutMultipart
		parties int
	}{
		{70, MultipartAnalyse, 2},
		{71, MultipartMalforme, 2}, // les compteurs restent ceux de PHP
		{5200, MultipartMalforme, 0},
	}
	for _, c := range cas {
		f := strings.Repeat("B", c.n)
		r := analyserMultipart(corpsDeuxParties(f), "multipart/form-data; boundary="+f, false, LimitesMultipart{})
		if r.Statut != c.statut || r.Parties != c.parties || r.LongueurFrontiere != c.n {
			t.Errorf("frontière %d : statut=%s parties=%d longueur=%d, attendu %s %d %d",
				c.n, r.Statut, r.Parties, r.LongueurFrontiere, c.statut, c.parties, c.n)
		}
	}
	// Sans frontière : longueur 0 et pas de signal.
	if r := analyserMultipart(nil, "multipart/form-data", false, LimitesMultipart{}); r.LongueurFrontiere != 0 {
		t.Errorf("sans frontière : longueur %d, attendu 0", r.LongueurFrontiere)
	}
	// Corps tronqué : le statut « tronque » n'est pas écrasé par la frontière.
	f := strings.Repeat("B", 71)
	corps := corpsDeuxParties(f)
	r := analyserMultipart(corps[:len(corps)-10], "multipart/form-data; boundary="+f, true, LimitesMultipart{})
	if r.Statut != MultipartTronque {
		t.Errorf("tronqué : statut %s, attendu tronque", r.Statut)
	}
}

func TestPHPGeneriqueSignatures(t *testing.T) {
	r := LoadRules(ecrisRegles(t, corpusPHPGeneriqueTest))
	if _, c, rej, av := r.Integrite(); c != 6 || len(rej) != 0 || len(av) != 0 {
		t.Fatalf("charges=%d rejetes=%v avertis=%v", c, rej, av)
	}
	ids := func(e *EntreePHP) []string {
		var out []string
		for _, d := range r.EvaluerPHP(e) {
			out = append(out, d.RuleID)
		}
		return out
	}
	multi := func(n int, frontiere string) *EntreePHP {
		ps := make([]partieTest, n)
		for i := range ps {
			ps[i] = partieTest{nom: fmt.Sprintf("c%d", i), contenu: "v"}
		}
		corps := fabriquerMultipart(frontiere, ps, false)
		if len(corps) >= 1<<20 {
			t.Fatalf("corps de %d octets, attendu < 1 Mio", len(corps))
		}
		res := analyserMultipart(corps, "multipart/form-data; boundary="+frontiere, false, LimitesMultipart{})
		return &EntreePHP{Multipart: &res}
	}
	cas := []struct {
		nom  string
		e    *EntreePHP
		want string
	}{
		{"1021 parties", multi(1021, "BND"), "php-001"},
		{"1020 parties", multi(1020, "BND"), ""},
		{"frontière 70", multi(2, strings.Repeat("B", 70)), ""},
		{"frontière 71", multi(2, strings.Repeat("B", 71)), "php-004"},
		{"frontière 5121", multi(2, strings.Repeat("B", 5121)), "php-004,php-005"},
		{"cookie", &EntreePHP{CookieFauxPrefixe: true}, "php-003"},
		{"DTD", &EntreePHP{DTDXML: true}, "php-002"},
		{"rien", &EntreePHP{}, ""},
	}
	for _, c := range cas {
		if got := strings.Join(ids(c.e), ","); got != c.want {
			t.Errorf("%s : %q, attendu %q", c.nom, got, c.want)
		}
	}
	// La gravité réelle de chaque signature part au journal.
	for _, d := range r.EvaluerPHP(&EntreePHP{DTDXML: true, CookieFauxPrefixe: true}) {
		want := map[string]string{"php-002": "high", "php-003": "medium"}[d.RuleID]
		if d.Severity != want {
			t.Errorf("%s : gravité %q, attendu %q", d.RuleID, d.Severity, want)
		}
	}
}

func TestSignauxFrontiere(t *testing.T) {
	e := &EntreePHP{Multipart: &ResultatMultipart{LongueurFrontiere: 71}}
	if got := e.Signaux()["frontiere"]; got != 71 {
		t.Errorf("signals.frontiere = %d, attendu 71", got)
	}
	e = &EntreePHP{Multipart: &ResultatMultipart{}}
	if _, ok := e.Signaux()["frontiere"]; ok {
		t.Error("frontière absente : pas de clé frontiere")
	}
}

func TestPHPGeneriqueControlesSansRequete(t *testing.T) {
	for c, p := range map[string]string{"xml_dtd_prologue": "", "cookie_prefixe_normalise": "",
		"frontiere_longueur": "longueur_min"} {
		if controlesRequete[c] {
			t.Errorf("%s ne lit pas la requête", c)
		}
		if got, ok := parametreRequis[c]; !ok || got != p {
			t.Errorf("parametreRequis[%s] = (%q, %v), attendu %q", c, got, ok, p)
		}
	}
}

// bancPHPGenerique : banc multipart armé du corpus PHP générique.
func bancPHPGenerique(t *testing.T) *bancMultipart {
	t.Helper()
	b := nouveauBancMultipart(t, nil)
	b.s.rules = LoadRules(ecrisRegles(t, corpusPHPGeneriqueTest))
	if _, c, rej, av := b.s.rules.Integrite(); c != 6 || len(rej) != 0 || len(av) != 0 {
		t.Fatalf("charges=%d rejetes=%v avertis=%v", c, rej, av)
	}
	return b
}

func TestPHPGeneriquePropfindDTDJournalise(t *testing.T) {
	b := bancPHPGenerique(t)
	// Les deux sémaphores sont pleins : le prologue se capture SANS jeton.
	b.s.capturesMultipart = make(chan struct{}, 1)
	b.s.capturesUrlencoded = make(chan struct{}, 1)
	b.s.capturesMultipart <- struct{}{}
	b.s.capturesUrlencoded <- struct{}{}
	corps := append([]byte(pocDTD), bytes.Repeat([]byte(" "), 10<<10-len(pocDTD))...)
	b.requeteNC("PROPFIND", "/remote.php/dav/files/alice/", ipPublique,
		http.Header{"Content-Type": {"application/xml"}, "Depth": {"1"}}, bytes.NewReader(corps))
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	d := lignesDe(ls, "php_requete")
	if len(d) != 1 || d[0]["rule_id"] != "php-002" || d[0]["severity"] != "high" || d[0]["action"] != "detect" {
		t.Fatalf("une ligne php-002 high attendue, eu %v", ls)
	}
	for _, l := range ls {
		if c, _ := l["category"].(string); strings.Contains(c, "concurrence") {
			t.Errorf("ligne de concurrence inattendue : %v", l)
		}
	}
	if len(b.s.capturesMultipart) != 1 || len(b.s.capturesUrlencoded) != 1 {
		t.Errorf("jetons modifiés : %d et %d, attendu 1 et 1", len(b.s.capturesMultipart), len(b.s.capturesUrlencoded))
	}
	// Ni DTD, ni uid, ni nom au journal.
	if brut := b.journalBrut(t); strings.Contains(brut, "ENTITY") || strings.Contains(brut, "alice") || strings.Contains(brut, "https://x/") {
		t.Errorf("le journal contient du corps ou l'uid : %s", brut)
	}
	b.verifierSansSanction(t, ipPublique)
}

// Le DTD au-delà de la fenêtre de 4 096 octets n'est jamais lu.
func TestPHPGeneriqueDTDHorsFenetre(t *testing.T) {
	b := bancPHPGenerique(t)
	corps := append(bytes.Repeat([]byte(" "), prologueXMLMax), []byte(pocDTD)...)
	b.requeteNC("PROPFIND", "/remote.php/dav/files/alice/", ipPublique,
		http.Header{"Content-Type": {"application/xml"}}, bytes.NewReader(corps))
	if ls := lignesDe(b.lignes(t), "php_requete"); len(ls) != 0 {
		t.Errorf("DTD hors fenêtre : aucune ligne attendue, eu %v", ls)
	}
}

func TestPHPGeneriquePropfindLegitimeMuet(t *testing.T) {
	b := bancPHPGenerique(t)
	propfind := `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>`
	b.requeteNC("PROPFIND", "/remote.php/dav/files/alice/", ipPublique,
		http.Header{"Content-Type": {"application/xml"}, "Depth": {"1"},
			"Cookie": {"__Host-nc_sameSiteCookielax=true; __Host-nc_sameSiteCookiestrict=true; oc1=s"}},
		strings.NewReader(propfind))
	if ls := b.lignes(t); len(ls) != 0 {
		t.Errorf("trafic légitime : aucune ligne attendue, eu %v", ls)
	}
}

func TestPHPGeneriqueCookieFauxPrefixeJournalise(t *testing.T) {
	b := bancPHPGenerique(t)
	b.requeteNC(http.MethodGet, "/index.php/apps/files", ipPublique,
		http.Header{"Cookie": {"a=1", "_[Host-nc_sameSiteCookiestrict=SECRET"}}, nil)
	ls := lignesDe(b.lignes(t), "php_requete")
	if len(ls) != 1 || ls[0]["rule_id"] != "php-003" || ls[0]["severity"] != "medium" {
		t.Fatalf("une ligne php-003 attendue, eu %v", b.lignes(t))
	}
	if strings.Contains(b.journalBrut(t), "SECRET") {
		t.Error("la valeur du cookie ne doit pas figurer au journal")
	}
}

// R-PHP4 : une frontière de 71 caractères donne php-004 ET le statut malforme,
// avec les compteurs de PHP ; les autres signatures du même envoi restent évaluées.
func TestPHPGeneriqueFrontiereLongueJournalise(t *testing.T) {
	b := bancPHPGenerique(t)
	f := strings.Repeat("B", 71)
	ps := make([]partieTest, 1021)
	for i := range ps {
		ps[i] = partieTest{nom: fmt.Sprintf("c%d", i), contenu: "v"}
	}
	corps := fabriquerMultipart(f, ps, false)
	b.envoyer("nc.example", "/index.php", ipPublique, "multipart/form-data; boundary="+f, bytes.NewReader(corps))
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	var ids []string
	for _, l := range lignesDe(ls, "php_requete") {
		ids = append(ids, l["rule_id"].(string))
		if n := signalLigne(t, l, "frontiere"); n != 71 {
			t.Errorf("signals.frontiere = %d, attendu 71", n)
		}
		if n := signalLigne(t, l, "parties"); n != 1021 {
			t.Errorf("signals.parties = %d, attendu 1021", n)
		}
	}
	if strings.Join(ids, ",") != "php-001,php-004" {
		t.Errorf("signatures %v, attendu php-001 et php-004", ids)
	}
	if m := lignesDe(ls, "multipart-malforme"); len(m) != 1 {
		t.Errorf("une ligne multipart-malforme attendue, eu %v", ls)
	}
	if strings.Contains(b.journalBrut(t), strings.Repeat("B", 71)) {
		t.Error("la frontière ne doit pas figurer au journal")
	}
}

// I1 : cookieFauxPrefixe n'est jamais appelé sans signature cookie_prefixe_normalise
// chargée, ni avant le relais ; chargée, il l'est une fois, après la réponse.
func TestCookieFauxPrefixeSeulementSiChargee(t *testing.T) {
	appels := 0
	avant := cookieFauxPrefixePHP
	cookieFauxPrefixePHP = func(l []string) bool { appels++; return avant(l) }
	t.Cleanup(func() { cookieFauxPrefixePHP = avant })
	entetes := http.Header{"Cookie": {"_[Host-x=y"}}

	// Corpus sans la signature : aucun appel.
	b := nouveauBancMultipart(t, nil)
	b.requeteNC(http.MethodGet, "/index.php/apps/files", ipPublique, entetes, nil)
	if appels != 0 {
		t.Errorf("sans signature chargée : %d appel(s), attendu 0", appels)
	}
	// Avec la signature : un appel, et pas avant le relais.
	appels = 0
	e := b.s.nouvelleEntreePHP(httptest.NewRequest(http.MethodGet, "http://nc.example/", nil), "")
	if appels != 0 || e.CookieFauxPrefixe {
		t.Errorf("nouvelleEntreePHP ne doit pas examiner les cookies (appels=%d)", appels)
	}
	appels = 0
	b = bancPHPGenerique(t)
	b.requeteNC(http.MethodGet, "/index.php/apps/files", ipPublique, entetes, nil)
	if appels != 1 {
		t.Errorf("signature chargée : %d appel(s), attendu 1", appels)
	}
}

// R12 : une IP privée est analysée et journalisée « local ».
func TestPHPGeneriqueIPPriveeLocal(t *testing.T) {
	b := bancPHPGenerique(t)
	corps := append([]byte(pocDTD), bytes.Repeat([]byte(" "), 1024)...)
	b.requeteNC("PROPFIND", "/remote.php/dav/files/alice/", "192.168.1.10",
		http.Header{"Content-Type": {"application/xml"}, "Cookie": {"_[Host-x=y"}}, bytes.NewReader(corps))
	ls := lignesDe(b.lignes(t), "php_requete")
	if len(ls) != 2 {
		t.Fatalf("deux lignes (php-002, php-003) attendues, eu %v", b.lignes(t))
	}
	for _, l := range ls {
		if l["client_ip"] != "local" {
			t.Errorf("client_ip = %v, attendu local", l["client_ip"])
		}
	}
	if strings.Contains(b.journalBrut(t), "192.168.1.10") {
		t.Error("l'adresse privée ne doit pas figurer au journal")
	}
}
