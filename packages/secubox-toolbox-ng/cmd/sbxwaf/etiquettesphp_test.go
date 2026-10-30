// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — tests des étiquettes d'outil (#3273)
package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Corpus PROPRE à ces tests : Roundcube (rc-001, rc-002) et la sonde PHP-CGI
// (php-007, seule étiquette qui vaut un signal), en detect.
const corpusEtiquettesTest = `{"categories": {
 "roundcube": {"name": "R", "severity": "high", "mode": "detect",
  "structural": [
   {"id": "rc-001", "check": "rc_from_invalide", "severity": "critical", "services": ["roundcube"], "cve": "CVE-2025-49113"},
   {"id": "rc-002", "check": "filename_session", "severity": "high", "services": ["roundcube"], "cve": "CVE-2025-49113"}
  ]},
 "php_requete": {"name": "Q", "severity": "medium", "mode": "detect",
  "structural": [
   {"id": "php-007", "check": "sonde_php_cgi", "severity": "medium", "cve": "CVE-2024-4577"}
  ]}}}`

const ctPoC = "multipart/form-data; boundary=------a_rule_for_WAF_to_block_fool_exploitation"

func TestSondePHPCGI(t *testing.T) {
	cas := map[string]bool{
		"-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input": true,
		"%ADd+allow_url_include=1":                                    true,
		"%2dd+allow_url_include=1":                                    true,
		"a=1&-d+allow_url_include=1":                                  true,
		"-d+ALLOW_URL_INCLUDE=1":                                      true,
		"q=allow_url_include":                                         false,
		"x-d+y&allow_url_include=1":                                   false,
		"":                                                            false,
	}
	for q, want := range cas {
		if got := sondePHPCGI(q); got != want {
			t.Errorf("sondePHPCGI(%q) = %v, attendu %v", q, got, want)
		}
	}
}

func TestEtiquettesOutilPHP(t *testing.T) {
	req := func(methode, cible string, h http.Header) (*http.Request, string) {
		r := httptest.NewRequest(methode, cible, nil)
		for k, vs := range h {
			for _, v := range vs {
				r.Header.Add(k, v)
			}
		}
		return r, r.URL.EscapedPath()
	}
	cas := []struct {
		nom, cible string
		h          http.Header
		want       []string
	}{
		{"boundary PoC", "http://webmail.example/", http.Header{"Content-Type": {ctPoC}}, []string{"poc-cve-2025-49113"}},
		{"chemin graphapi", "http://nc.example/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php", nil, []string{"sonde-owncloud"}},
		{"chemin graphapi casse", "http://nc.example/Apps/GraphAPI/x.php", nil, []string{"sonde-owncloud"}},
		{"paramètres OC", "http://nc.example/x?OC-Credential=x&OC-Signature=y", nil, []string{"sonde-owncloud"}},
		{"en-tête OC", "http://nc.example/x", http.Header{"Oc-Signature": {"y"}}, []string{"sonde-owncloud"}},
		{"chemin %0a", "http://nc.example/index.php%0a", nil, []string{"sonde-cve-2019-11043"}},
		{"chemin %0D", "http://nc.example/index.php%0D", nil, []string{"sonde-cve-2019-11043"}},
		{"sonde CGI", "http://nc.example/index.php?-d+allow_url_include%3d1", nil, []string{"sonde-php-cgi"}},
		{"ordre", "http://nc.example/apps/graphapi/x%0a?-d+allow_url_include=1", http.Header{"Content-Type": {ctPoC}},
			[]string{"poc-cve-2025-49113", "sonde-php-cgi", "sonde-owncloud", "sonde-cve-2019-11043"}},
		{"ordinaire", "http://nc.example/index.php?a=1", http.Header{"Content-Type": {"multipart/form-data; boundary=BND"}}, nil},
	}
	for _, c := range cas {
		r, brut := req("GET", c.cible, c.h)
		if got := etiquettesOutilPHP(r, brut); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s : %v, attendu %v", c.nom, got, c.want)
		}
	}
}

// bancEtiquettes : webmail.example (roundcube) et nc.example (nextcloud), PHP.
func bancEtiquettes(t *testing.T) *bancMultipart {
	t.Helper()
	b := nouveauBancMultipart(t, nil)
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"roundcube": {"legit_paths": []}, "nextcloud": {"legit_paths": []}},
		"vhosts": {"webmail.example": "roundcube", "nc.example": "nextcloud"},
		"php_services": ["roundcube", "nextcloud"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	b.s.vhostProfiles = vp
	b.s.rules = LoadRules(ecrisRegles(t, corpusEtiquettesTest))
	if _, c, rej, av := b.s.rules.Integrite(); c != 3 || len(rej) != 0 || len(av) != 0 {
		t.Fatalf("charges=%d rejetes=%v avertis=%v", c, rej, av)
	}
	return b
}

func (b *bancMultipart) requete(methode, hote, cible, ct string, corps []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(methode, "http://"+hote+cible, strings.NewReader(string(corps)))
	req.Host = hote
	req.RemoteAddr = ipPublique + ":40000"
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	rec := httptest.NewRecorder()
	b.s.handler().ServeHTTP(rec, req)
	return rec
}

// Une étiquette seule ne crée jamais de ligne (sauf la sonde PHP-CGI).
func TestEtiquetteSeuleSansLigne(t *testing.T) {
	b := bancEtiquettes(t)
	benin := fabriquerMultipart("------a_rule_for_WAF_to_block_fool_exploitation",
		[]partieTest{{nom: "_task", contenu: "mail"}}, false)
	b.requete("POST", "webmail.example", "/?_task=mail", ctPoC, benin)
	b.requete("GET", "nc.example", "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php", "", nil)
	b.requete("GET", "nc.example", "/index.php%0a", "", nil)
	if ls := b.lignes(t); len(ls) != 0 {
		t.Fatalf("aucune ligne attendue, eu %v", ls)
	}
}

// Une étiquette aggrave une ligne existante : trait et outil, gravité intacte.
func TestEtiquetteAggraveLaDetection(t *testing.T) {
	b := bancEtiquettes(t)
	corps := fabriquerMultipart("------a_rule_for_WAF_to_block_fool_exploitation", []partieTest{
		{nom: "_file[]", filename: `x|b:0;preferences|s:179:\"a:3:{i:0;s:57:\".png`, fichier: true, contenu: "x"},
	}, false)
	b.requete("POST", "webmail.example", "/?_task=settings&_action=upload&_from=edit-!x", ctPoC, corps)
	ls := lignesDe(b.lignes(t), "roundcube")
	if len(ls) != 2 {
		t.Fatalf("deux lignes attendues, eu %v", b.lignes(t))
	}
	sev := map[string]string{"rc-001": "critical", "rc-002": "high"}
	for _, l := range ls {
		id, _ := l["rule_id"].(string)
		if l["severity"] != sev[id] {
			t.Errorf("%s : gravité %v, attendu %s", id, l["severity"], sev[id])
		}
		if l["tool"] != "poc-cve-2025-49113" {
			t.Errorf("%s : tool = %v", id, l["tool"])
		}
		tr, _ := l["behavior_traits"].([]any)
		if len(tr) != 1 || tr[0] != "outil:poc-cve-2025-49113" {
			t.Errorf("%s : behavior_traits = %v", id, l["behavior_traits"])
		}
		if strings.Contains(toutTexte(l), "a_rule_for_WAF") {
			t.Errorf("la frontière ne doit jamais être journalisée : %v", l)
		}
	}
}

// Un outil identifié par l'UA prime sur l'étiquette, qui reste en trait.
func TestEtiquetteUAPrimeSurTool(t *testing.T) {
	b := bancEtiquettes(t)
	req := httptest.NewRequest("GET", "http://webmail.example/?_from=edit-!x", nil)
	req.Host = "webmail.example"
	req.RemoteAddr = ipPublique + ":40000"
	req.Header.Set("User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")
	req.Header.Set("Oc-Signature", "y")
	b.s.handler().ServeHTTP(httptest.NewRecorder(), req)
	ls := lignesDe(b.lignes(t), "roundcube")
	if len(ls) != 1 || ls[0]["tool"] != "sqlmap" {
		t.Fatalf("tool sqlmap attendu : %v", b.lignes(t))
	}
	if tr, _ := ls[0]["behavior_traits"].([]any); len(tr) != 1 || tr[0] != "outil:sonde-owncloud" {
		t.Errorf("behavior_traits = %v", ls[0]["behavior_traits"])
	}
}

// La sonde -d allow_url_include vaut un signal medium à elle seule.
func TestSondePHPCGISignalMoyen(t *testing.T) {
	b := bancEtiquettes(t)
	b.requete("GET", "nc.example", "/index.php?-d+allow_url_include%3d1", "", nil)
	ls := lignesDe(b.lignes(t), "php_requete")
	if len(ls) != 1 || ls[0]["rule_id"] != "php-007" || ls[0]["severity"] != "medium" || ls[0]["tool"] != "sonde-php-cgi" {
		t.Fatalf("une ligne php-007 medium attendue, eu %v", b.lignes(t))
	}
	if tr, _ := ls[0]["behavior_traits"].([]any); len(tr) != 1 || tr[0] != "outil:sonde-php-cgi" {
		t.Errorf("behavior_traits = %v", ls[0]["behavior_traits"])
	}
	// Vhost non PHP : aucune entrée, aucune ligne.
	b2 := bancEtiquettes(t)
	b2.requete("GET", "autre.example", "/index.php?-d+allow_url_include%3d1", "", nil)
	if ls := b2.lignes(t); len(ls) != 0 {
		t.Errorf("vhost non PHP : aucune ligne attendue, eu %v", ls)
	}
}

func TestSondePHPCGIInscriteDansControlesRequete(t *testing.T) {
	if !controlesRequete["sonde_php_cgi"] {
		t.Error("sonde_php_cgi lit la chaîne de requête : elle doit être dans controlesRequete")
	}
}
