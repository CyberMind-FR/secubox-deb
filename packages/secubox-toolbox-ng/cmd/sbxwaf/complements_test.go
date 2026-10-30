// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — tests des compléments C1 à C5 (#3273)
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Corpus PROPRE à ces tests : php2shell-005 à -008 et php-006, en detect.
const corpusComplementsTest = `{"_meta": {"version": "t"}, "categories": {
 "php2shell": {"name": "P", "severity": "high", "mode": "detect",
  "patterns": [{"id": "p-1", "pattern": "zzzjamais"}],
  "structural": [
   {"id": "php2shell-001", "check": "upload_progress_fichiers", "params": {"fichiers_apres_min": 2}, "cve": "CVE-2026-109618"},
   {"id": "php2shell-005", "check": "corps_sans_longueur", "severity": "high"},
   {"id": "php2shell-006", "check": "entetes_partie", "params": {"entetes_min": 9}, "severity": "high", "seuil": "provisoire, non sourcé (2026-10-29)"},
   {"id": "php2shell-007", "check": "fichiers_vides", "params": {"vides_min": 21}, "severity": "high", "seuil": "provisoire, non sourcé (2026-10-29)"},
   {"id": "php2shell-008", "check": "variables_nombre", "params": {"variables_min": 1001}, "severity": "medium"}
  ]},
 "php_requete": {"name": "Q", "severity": "medium", "mode": "detect",
  "patterns": [{"id": "php-p", "pattern": "zzzjamais"}],
  "structural": [
   {"id": "php-006", "check": "upload_progress_present", "severity": "medium", "cve": "CVE-2026-115560"}
  ]}}}`

func TestCorpsSansLongueur(t *testing.T) {
	mp := "multipart/form-data; boundary=x"
	ue := "application/x-www-form-urlencoded"
	cas := []struct {
		nom, methode, ct string
		cl               int64
		te               []string
		want             bool
	}{
		{"multipart sans longueur", "POST", mp, -1, nil, true},
		{"urlencoded chunked", "POST", ue, 0, []string{"chunked"}, true},
		{"post minuscule", "post", mp, -1, nil, true},
		{"multipart avec longueur", "POST", mp, 10, nil, false},
		{"PUT multipart sans longueur", "PUT", mp, -1, nil, false},
		{"json sans longueur", "POST", "application/json", -1, nil, false},
		{"GET", "GET", "", -1, nil, false},
	}
	for _, c := range cas {
		r := httptest.NewRequest(c.methode, "http://nc.example/x", strings.NewReader(""))
		r.ContentLength, r.TransferEncoding = c.cl, c.te
		r.Header.Set("Content-Type", c.ct)
		if got := corpsSansLongueur(r); got != c.want {
			t.Errorf("%s : %v, attendu %v", c.nom, got, c.want)
		}
	}
}

func TestAnalyserMultipartEntetesPartie(t *testing.T) {
	var b strings.Builder
	b.WriteString("--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n")
	for i := 0; i < 11; i++ {
		fmt.Fprintf(&b, "X-%d: v\r\n", i) // 1 + 11 = 12 lignes, continuation comprise
	}
	b.WriteString(" suite\r\n") // la 13e est une continuation : 13
	b.WriteString("\r\nv\r\n--BND--\r\n")
	r := analyserMultipart([]byte(b.String()), ctTest, false, LimitesMultipart{})
	if r.EntetesPartieMax != 13 {
		t.Errorf("EntetesPartieMax = %d, attendu 13", r.EntetesPartieMax)
	}
	var c strings.Builder
	c.WriteString("--BND\r\nContent-Disposition: form-data; name=\"a\"\r\n")
	for i := 0; i < 11; i++ {
		fmt.Fprintf(&c, "X-%d: v\r\n", i)
	}
	c.WriteString("\r\nv\r\n--BND--\r\n")
	if r := analyserMultipart([]byte(c.String()), ctTest, false, LimitesMultipart{}); r.EntetesPartieMax != 12 {
		t.Errorf("EntetesPartieMax = %d, attendu 12", r.EntetesPartieMax)
	}
	legit := fabriquerMultipart("BND", []partieTest{{nom: "f", filename: "a.jpg", fichier: true, contenu: "x"}}, false)
	legit = []byte(strings.Replace(string(legit), "\r\n\r\nx", "\r\nContent-Type: image/jpeg\r\n\r\nx", 1))
	if r := analyserMultipart(legit, ctTest, false, LimitesMultipart{}); r.EntetesPartieMax != 2 {
		t.Errorf("envoi légitime : %d, attendu 2", r.EntetesPartieMax)
	}
	// Le maximum porte sur les parties : une grosse partie puis une petite.
	deux := "--BND\r\nContent-Disposition: form-data; name=\"a\"\r\nA: 1\r\nB: 2\r\n\r\nv\r\n" +
		"--BND\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nv\r\n--BND--\r\n"
	if r := analyserMultipart([]byte(deux), ctTest, false, LimitesMultipart{}); r.EntetesPartieMax != 3 {
		t.Errorf("maximum sur les parties : %d, attendu 3", r.EntetesPartieMax)
	}
}

func TestAnalyserMultipartFichiersVides(t *testing.T) {
	ps := make([]partieTest, 25)
	for i := range ps {
		ps[i] = partieTest{nom: fmt.Sprintf("f%d", i), filename: "", fichier: true, contenu: ""}
	}
	r := analyserMultipart(fabriquerMultipart("BND", ps, false), ctTest, false, LimitesMultipart{})
	if r.FichiersVides != 25 || r.PartiesFichier != 25 {
		t.Errorf("FichiersVides=%d PartiesFichier=%d, attendu 25 et 25", r.FichiersVides, r.PartiesFichier)
	}
	if s := r.Signaux(); s["fichiers_vides"] != 25 || s["entetes_partie_max"] != 1 {
		t.Errorf("signaux : %v", s)
	}
	mixte := fabriquerMultipart("BND", []partieTest{
		{nom: "a", filename: "x.txt", fichier: true, contenu: "y"},
		{nom: "b", filename: "", fichier: true, contenu: ""},
	}, false)
	if r := analyserMultipart(mixte, ctTest, false, LimitesMultipart{}); r.FichiersVides != 1 {
		t.Errorf("mixte : FichiersVides = %d, attendu 1", r.FichiersVides)
	}
}

func TestComplementsSignatures(t *testing.T) {
	r := LoadRules(ecrisRegles(t, corpusComplementsTest))
	if _, c, rej, av := r.Integrite(); c != 8 || len(rej) != 0 || len(av) != 0 {
		t.Fatalf("charges=%d rejetes=%v avertis=%v", c, rej, av)
	}
	ids := func(e *EntreePHP) string {
		var out []string
		for _, d := range r.EvaluerPHP(e) {
			out = append(out, d.RuleID)
		}
		return strings.Join(out, ",")
	}
	vars := func(n int) ParametresPHP {
		var b strings.Builder
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte('&')
			}
			fmt.Fprintf(&b, "v%d=1", i)
		}
		return lireParametresPHP(b.String())
	}
	v1001, v1000 := vars(1001), vars(1000)
	cas := []struct {
		nom  string
		e    *EntreePHP
		want string
	}{
		{"sans longueur", &EntreePHP{SansLongueur: true}, "php2shell-005"},
		{"entêtes 9", &EntreePHP{Multipart: &ResultatMultipart{EntetesPartieMax: 9}}, "php2shell-006"},
		{"entêtes 8", &EntreePHP{Multipart: &ResultatMultipart{EntetesPartieMax: 8}}, ""},
		{"vides 21", &EntreePHP{Multipart: &ResultatMultipart{FichiersVides: 21}}, "php2shell-007"},
		{"vides 20", &EntreePHP{Multipart: &ResultatMultipart{FichiersVides: 20}}, ""},
		{"corps 1001", &EntreePHP{Corps: &v1001}, "php2shell-008"},
		{"corps 1000", &EntreePHP{Corps: &v1000}, ""},
		{"requête 1001", &EntreePHP{Requete: v1001}, "php2shell-008"},
		{"requête 1000", &EntreePHP{Requete: v1000}, ""},
		{"progress sans fichier", &EntreePHP{Multipart: &ResultatMultipart{Progress: true}}, "php-006"},
		{"rien", &EntreePHP{}, ""},
	}
	for _, c := range cas {
		if got := ids(c.e); got != c.want {
			t.Errorf("%s : %q, attendu %q", c.nom, got, c.want)
		}
	}
	// Les gravités viennent des signatures.
	sev := map[string]string{}
	for _, d := range r.EvaluerPHP(&EntreePHP{SansLongueur: true, Requete: v1001,
		Multipart: &ResultatMultipart{Progress: true, EntetesPartieMax: 9, FichiersVides: 21}}) {
		sev[d.RuleID] = d.Severity
	}
	for id, want := range map[string]string{"php2shell-005": "high", "php2shell-006": "high",
		"php2shell-007": "high", "php2shell-008": "medium", "php-006": "medium"} {
		if sev[id] != want {
			t.Errorf("%s : gravité %q, attendu %q", id, sev[id], want)
		}
	}
	// La requête n'est lue que pour variables_nombre ; le paramètre est requis.
	if !r.litLaRequete() {
		t.Error("variables_nombre doit inscrire la lecture de la requête")
	}
	for c, p := range map[string]string{"corps_sans_longueur": "", "entetes_partie": "entetes_min",
		"fichiers_vides": "vides_min", "variables_nombre": "variables_min", "upload_progress_present": ""} {
		if got, ok := parametreRequis[c]; !ok || got != p {
			t.Errorf("parametreRequis[%s] = (%q, %v), attendu %q", c, got, ok, p)
		}
	}
}

func TestComplementsSignaux(t *testing.T) {
	p := lireParametresPHP("a=1&b=2&c=3")
	q := lireParametresPHP("a=1")
	e := &EntreePHP{Requete: q, Corps: &p, Multipart: &ResultatMultipart{EntetesPartieMax: 4, FichiersVides: 2}}
	s := e.Signaux()
	if s["variables"] != 3 || s["entetes_partie_max"] != 4 || s["fichiers_vides"] != 2 {
		t.Errorf("signaux : %v", s)
	}
	if _, ok := (&EntreePHP{}).Signaux()["variables"]; ok {
		t.Error("variables ne doit pas figurer à 0")
	}
}

func bancComplements(t *testing.T) *bancMultipart {
	t.Helper()
	b := nouveauBancMultipart(t, nil)
	b.s.rules = LoadRules(ecrisRegles(t, corpusComplementsTest))
	if _, c, rej, av := b.s.rules.Integrite(); c != 8 || len(rej) != 0 || len(av) != 0 {
		t.Fatalf("charges=%d rejetes=%v avertis=%v", c, rej, av)
	}
	return b
}

func TestCorpsChunkedSansLongueurJournalise(t *testing.T) {
	b := bancComplements(t)
	corps := fabriquerMultipart("BND", []partieTest{{nom: "a", contenu: "v"}}, false)
	rec := b.requeteNC(http.MethodPost, "/index.php/apps/files", ipPublique,
		http.Header{"Content-Type": {"multipart/form-data; boundary=BND"}},
		io.MultiReader(strings.NewReader(string(corps))))
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d", rec.Code)
	}
	b.verifierRecu(t, corps)
	ls := lignesDe(b.lignes(t), "php2shell")
	if len(ls) != 1 || ls[0]["rule_id"] != "php2shell-005" || ls[0]["severity"] != "high" || ls[0]["action"] != "detect" {
		t.Fatalf("une ligne php2shell-005 high attendue, eu %v", b.lignes(t))
	}
	b.verifierSansSanction(t, ipPublique)
}

func TestComplementsVariablesRequeteJournalise(t *testing.T) {
	b := bancComplements(t)
	var q strings.Builder
	for i := 0; i < 1001; i++ {
		fmt.Fprintf(&q, "v%d=1&", i)
	}
	b.requeteNC(http.MethodGet, "/index.php/apps/files?"+q.String(), ipPublique, nil, nil)
	ls := lignesDe(b.lignes(t), "php2shell")
	if len(ls) != 1 || ls[0]["rule_id"] != "php2shell-008" || ls[0]["severity"] != "medium" {
		t.Fatalf("une ligne php2shell-008 attendue, eu %v", b.lignes(t))
	}
	if s, _ := ls[0]["signals"].(map[string]any); s["variables"] != float64(1001) {
		t.Errorf("signals = %v, attendu variables 1001", ls[0]["signals"])
	}
}

func TestComplementsVariablesCorpsTronque(t *testing.T) {
	// Corps urlencoded coupé par la fenêtre : C4 ne compte que ce qu'il a vu.
	b := bancComplements(t)
	b.s.maxBodyInspect = 4096
	var c strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&c, "v%d=1&", i)
	}
	b.requeteNC(http.MethodPost, "/index.php/apps/files", ipPublique,
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, strings.NewReader(c.String()))
	for _, l := range lignesDe(b.lignes(t), "php2shell") {
		if l["rule_id"] == "php2shell-008" {
			t.Errorf("C4 ne doit pas se déclencher sur un corps tronqué de moins de 1001 variables vues : %v", l)
		}
	}
}

func TestComplementsGETSansLigne(t *testing.T) {
	b := bancComplements(t)
	b.requeteNC(http.MethodGet, "/index.php/apps/files?a=1", ipPublique, nil, nil)
	if ls := b.lignes(t); len(ls) != 0 {
		t.Errorf("GET ordinaire : aucune ligne attendue, eu %v", ls)
	}
}
