// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — tests des signatures Nextcloud (#3273, R-NC1, R-NC2, R-IMG2)
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Corpus PROPRE à ces tests : la catégorie nextcloud, en detect.
const corpusNextcloudTest = `{"_meta": {"version": "t"}, "categories": {"nextcloud": {"name": "N", "severity": "medium", "mode": "detect",
  "patterns": [{"id": "n-0", "pattern": "zzzjamais"}],
  "structural": [
   {"id": "nc-001", "check": "nc_partage_federe", "severity": "medium", "services": ["nextcloud"]},
   {"id": "nc-002", "check": "nc_partage_federe_rafale", "params": {"appels_min": 6}, "severity": "high", "services": ["nextcloud"]},
   {"id": "nc-003", "check": "nc_proxy_agenda", "severity": "medium", "services": ["nextcloud"]},
   {"id": "nc-004", "check": "nc_proxy_agenda_autrui", "severity": "high", "services": ["nextcloud"]},
   {"id": "nc-005", "check": "nc_put_non_raster", "severity": "medium", "services": ["nextcloud"]}
  ]}}}`

func TestCheminPartageFedere(t *testing.T) {
	cas := map[string]bool{
		"/ocm/shares":                 true,
		"/index.php/ocm/shares":       true,
		"/ocs/v1.php/cloud/shares":    true,
		"/ocs/v2.php/cloud/shares":    true,
		"/ocm/shares/":                true,
		"/ocs/v2.php/cloud/shares/":   true,
		"/ocs/v2.php/cloud/shares/12": false,
		"/OCM/shares":                 false,
		"/ocm/shares//":               false,
		"/ocm":                        false,
		"":                            false,
	}
	for c, attendu := range cas {
		if got := cheminPartageFedere(c); got != attendu {
			t.Errorf("cheminPartageFedere(%q) = %v, attendu %v", c, got, attendu)
		}
	}
}

func TestSessionNextcloud(t *testing.T) {
	cas := []struct {
		lignes  []string
		attendu bool
	}{
		{[]string{"ocabcdef1234=x"}, true},
		{[]string{"a=1", "nc_session_id=1"}, true},
		{[]string{"oc_sessionPassphrase=p"}, true},
		{[]string{"nc_token=t"}, true},
		{[]string{"x=1; nc_username=alice"}, true},
		{[]string{"ocabc=1"}, false},
		{[]string{"ocABCDEF1234=1"}, false},
		{[]string{"ocabcdef12345=1"}, false},
		{[]string{"foo=1"}, false},
		{nil, false},
	}
	for _, c := range cas {
		if got := sessionNextcloud(c.lignes); got != c.attendu {
			t.Errorf("sessionNextcloud(%q) = %v, attendu %v", c.lignes, got, c.attendu)
		}
	}
}

func TestCompteurFenetre(t *testing.T) {
	if federationPeriode != 1200*time.Second || federationIPMax != 4096 || federationGarde != 64 {
		t.Fatalf("constantes %v/%d/%d, attendu 1200 s, 4096, 64", federationPeriode, federationIPMax, federationGarde)
	}
	t0 := time.Unix(1_800_000_000, 0)
	c := nouveauCompteurFenetre(federationPeriode, federationGarde, federationIPMax)
	var n int
	for i := 0; i < 6; i++ {
		n = c.noter("1.2.3.4", t0.Add(time.Duration(i)*time.Second))
		if n != i+1 {
			t.Errorf("appel %d : %d, attendu %d", i+1, n, i+1)
		}
	}
	if n = c.noter("1.2.3.4", t0.Add(1201*time.Second)); n != 5 {
		t.Errorf("à t0+1201 s : %d, attendu 5 (t0 et t0+1 sortis de la fenêtre)", n)
	}
	if n = c.noter("5.6.7.8", t0); n != 1 {
		t.Errorf("autre IP : %d, attendu 1", n)
	}

	// Plafond par IP : jamais plus de garde horodatages, ni dans le compte.
	g := nouveauCompteurFenetre(federationPeriode, 3, 10)
	for i := 0; i < 10; i++ {
		n = g.noter("1.2.3.4", t0.Add(time.Duration(i)*time.Millisecond))
	}
	if n != 3 || len(g.parIP["1.2.3.4"]) != 3 || cap(g.parIP["1.2.3.4"]) > 4 {
		t.Errorf("garde 3 : rend %d, %d horodatages (cap %d), attendu 3", n, len(g.parIP["1.2.3.4"]), cap(g.parIP["1.2.3.4"]))
	}

	// Carte pleine : la 3e IP n'est pas suivie et rend 1.
	p := nouveauCompteurFenetre(federationPeriode, federationGarde, 2)
	p.noter("10.0.0.1", t0)
	p.noter("10.0.0.2", t0)
	if n = p.noter("10.0.0.3", t0.Add(time.Second)); n != 1 {
		t.Errorf("3e IP, carte pleine : %d, attendu 1", n)
	}
	if len(p.parIP) > 2 {
		t.Errorf("carte : %d IP, attendu <= 2", len(p.parIP))
	}
	// La 3e IP n'est toujours pas suivie : rend 1 à chaque appel.
	if n = p.noter("10.0.0.3", t0.Add(2*time.Second)); n != 1 {
		t.Errorf("3e IP, second appel : %d, attendu 1", n)
	}
	// Les deux premières n'ont plus d'horodatage récent : purgées, la nouvelle entre.
	tard := t0.Add(federationPeriode + time.Second)
	p.noter("10.0.0.3", tard)
	if n = p.noter("10.0.0.3", tard.Add(time.Second)); n != 2 {
		t.Errorf("après purge : %d, attendu 2 (IP suivie)", n)
	}
	if len(p.parIP) > 2 {
		t.Errorf("après purge : %d IP, attendu <= 2", len(p.parIP))
	}
}

// Le compteur est partagé entre goroutines : sous -race, aucune course, et la
// mémoire reste bornée (ipMax IP, garde horodatages par IP).
func TestCompteurFenetreConcurrent(t *testing.T) {
	c := nouveauCompteurFenetre(federationPeriode, 8, 16)
	t0 := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ip := fmt.Sprintf("198.51.100.%d", (g*7+i)%40)
				if n := c.noter(ip, t0.Add(time.Duration(i)*time.Millisecond)); n < 1 || n > 8 {
					t.Errorf("noter rend %d, attendu dans [1, 8]", n)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.parIP) > 16 {
		t.Errorf("%d IP suivies, attendu <= 16", len(c.parIP))
	}
	for ip, ts := range c.parIP {
		if len(ts) > 8 || cap(ts) > 16 {
			t.Errorf("%s : %d horodatages (cap %d), attendu <= 8", ip, len(ts), cap(ts))
		}
	}
}

func TestProxyAgenda(t *testing.T) {
	cas := []struct {
		methode, chemin string
		uid             string
		ok              bool
	}{
		{"PROPPATCH", "/remote.php/dav/principals/users/alice/calendar-proxy-write", "alice", true},
		{"proppatch", "/remote.php/dav/principals/users/alice/calendar-proxy-read/", "alice", true},
		{"PROPFIND", "/remote.php/dav/principals/users/alice/calendar-proxy-write", "", false},
		{"PROPPATCH", "/remote.php/dav/principals/users/alice/calendar-proxy-other", "", false},
		{"PROPPATCH", "/remote.php/dav/principals/users/alice", "", false},
		{"PROPPATCH", "/remote.php/dav/principals/users//calendar-proxy-write", "", false},
		{"PROPPATCH", "/remote.php/dav/principals/users/a/b/calendar-proxy-write", "", false},
	}
	for _, c := range cas {
		uid, ok := proxyAgenda(c.methode, c.chemin)
		if uid != c.uid || ok != c.ok {
			t.Errorf("proxyAgenda(%q, %q) = (%q, %v), attendu (%q, %v)", c.methode, c.chemin, uid, ok, c.uid, c.ok)
		}
	}
}

func basic(identifiants string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(identifiants))
}

func TestUtilisateurBasic(t *testing.T) {
	cas := []struct {
		entete, user string
		ok           bool
	}{
		{basic("bob:pw"), "bob", true},
		{"basic " + base64.StdEncoding.EncodeToString([]byte("bob:a:b")), "bob", true},
		{"Bearer x", "", false},
		{"Basic %%%", "", false},
		{"", "", false},
		{"Basic", "", false},
		{basic("sansdeuxpoints"), "", false},
	}
	for _, c := range cas {
		u, ok := utilisateurBasic(c.entete)
		if u != c.user || ok != c.ok {
			t.Errorf("utilisateurBasic(%q) = (%q, %v), attendu (%q, %v)", c.entete, u, ok, c.user, c.ok)
		}
	}
}

func TestExtensionRaster(t *testing.T) {
	cas := map[string]bool{"a.jpg": true, "a.JPEG": true, "a.png": true, "a.gif": true, "a.WebP": true,
		"a.pdf": false, "a.svg": false, "png": false, "a.png.pdf": false, "": false, "a.": false}
	for nom, attendu := range cas {
		if got := extensionRaster(nom); got != attendu {
			t.Errorf("extensionRaster(%q) = %v, attendu %v", nom, got, attendu)
		}
	}
}

func TestPutWebDAVPremierSegment(t *testing.T) {
	dest := "https://nc/remote.php/dav/files/alice/a.png"
	cas := []struct {
		methode, chemin, destination string
		nom                          string
		ok                           bool
	}{
		{"PUT", "/remote.php/dav/files/alice/x/photo.JPG", "", "photo.JPG", true},
		{"put", "/remote.php/dav/files/alice/photo.png", "", "photo.png", true},
		{"PUT", "/remote.php/dav/uploads/alice/123/1", dest, "a.png", true},
		{"PUT", "/remote.php/dav/uploads/alice/123/00001", dest, "a.png", true},
		{"PUT", "/remote.php/dav/uploads/alice/123/0", dest, "a.png", true},
		{"PUT", "/remote.php/dav/uploads/alice/123/2", dest, "", false},
		{"PUT", "/remote.php/dav/uploads/alice/123/x1", dest, "", false},
		{"PUT", "/remote.php/dav/uploads/alice/123/", dest, "", false},
		{"PUT", "/remote.php/dav/uploads/alice/123/1", "", "", false},
		{"PUT", "/remote.php/dav/uploads/alice/1", dest, "", false},
		{"PUT", "/remote.php/dav/files/alice/dossier/", "", "", false},
		{"GET", "/remote.php/dav/files/alice/x/photo.JPG", "", "", false},
		{"PUT", "/index.php/apps/files", "", "", false},
	}
	for _, c := range cas {
		nom, ok := putWebDAVPremierSegment(c.methode, c.chemin, c.destination)
		if nom != c.nom || ok != c.ok {
			t.Errorf("putWebDAVPremierSegment(%q, %q, %q) = (%q, %v), attendu (%q, %v)",
				c.methode, c.chemin, c.destination, nom, ok, c.nom, c.ok)
		}
	}
}

// bancNextcloud : banc multipart (nc.example = nextcloud, PHP) armé du corpus
// Nextcloud et d'un compteur de partages fédérés aux valeurs de production.
func bancNextcloud(t *testing.T, profils string) *bancMultipart {
	t.Helper()
	b := nouveauBancMultipart(t, nil)
	if profils != "" {
		vp, err := chargerVhostProfilesDepuis([]byte(profils))
		if err != nil {
			t.Fatal(err)
		}
		b.s.vhostProfiles = vp
	}
	b.s.rules = LoadRules(ecrisRegles(t, corpusNextcloudTest))
	if _, c, rej, av := b.s.rules.Integrite(); c != 6 || len(rej) != 0 || len(av) != 0 {
		t.Fatalf("charges=%d rejetes=%v avertis=%v", c, rej, av)
	}
	b.s.appelsFederes = nouveauCompteurFenetre(federationPeriode, federationGarde, federationIPMax)
	return b
}

// requeteNC envoie une requête quelconque à nc.example.
func (b *bancMultipart) requeteNC(methode, chemin, ip string, entetes http.Header, corps io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(methode, "http://nc.example"+chemin, corps)
	req.Host = "nc.example"
	req.RemoteAddr = ip + ":40000"
	for k, vs := range entetes {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	b.s.handler().ServeHTTP(rec, req)
	return rec
}

// journalBrut : tout le texte du journal (pour vérifier ce qui n'y est jamais).
func (b *bancMultipart) journalBrut(t *testing.T) string {
	t.Helper()
	brut, err := os.ReadFile(b.journal)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(brut)
}

func TestNextcloudPartageFedere(t *testing.T) {
	b := bancNextcloud(t, "")
	ct := http.Header{"Content-Type": {"application/json"}}
	if rec := b.requeteNC(http.MethodPost, "/ocm/shares", ipPublique, ct, strings.NewReader(`{}`)); rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200 (detect ne bloque pas)", rec.Code)
	}
	ls := lignesDe(b.lignes(t), "nextcloud")
	if len(ls) != 1 || ls[0]["rule_id"] != "nc-001" || ls[0]["severity"] != "medium" ||
		ls[0]["action"] != "detect" || ls[0]["mode"] != "detect" {
		t.Fatalf("une ligne nc-001 medium attendue, eu %v", b.lignes(t))
	}
	avecAuth := http.Header{"Content-Type": {"application/json"}, "Authorization": {basic("alice:pw")}}
	b.requeteNC(http.MethodPost, "/ocm/shares", ipPublique, avecAuth, strings.NewReader(`{}`))
	avecSession := http.Header{"Content-Type": {"application/json"}, "Cookie": {"a=1", "nc_session_id=x"}}
	b.requeteNC(http.MethodPost, "/ocm/shares", ipPublique, avecSession, strings.NewReader(`{}`))
	if ls := lignesDe(b.lignes(t), "nextcloud"); len(ls) != 1 {
		t.Errorf("avec Authorization ou session : aucune ligne de plus attendue, eu %v", ls)
	}
	// R12 : une adresse privée est analysée, journalisée « local ».
	b.requeteNC(http.MethodPost, "/ocm/shares", "192.168.1.10", ct, strings.NewReader(`{}`))
	if ls := lignesDe(b.lignes(t), "nextcloud"); len(ls) != 2 || ls[1]["client_ip"] != "local" {
		t.Errorf("adresse privée : une ligne « local » attendue, eu %v", ls)
	}
	if strings.Contains(b.journalBrut(t), "192.168.1.10") {
		t.Error("l'adresse privée ne doit pas figurer au journal")
	}
	b.verifierSansSanction(t, ipPublique)
}

func TestNextcloudPartageFedereRafale(t *testing.T) {
	b := bancNextcloud(t, `{
		"services": {"nextcloud": {"legit_paths": []}},
		"vhosts": {"nc.example": "nextcloud"},
		"php_services": ["nextcloud"],
		"federation_vhosts": ["nc.example"]
	}`)
	ct := http.Header{"Content-Type": {"application/json"}}
	for i := 1; i <= 5; i++ {
		b.requeteNC(http.MethodPost, "/ocs/v2.php/cloud/shares", ipPublique, ct, strings.NewReader(`{}`))
		if ls := lignesDe(b.lignes(t), "nextcloud"); len(ls) != 0 {
			t.Fatalf("appel %d : aucune ligne attendue (fédération utilisée), eu %v", i, ls)
		}
	}
	b.requeteNC(http.MethodPost, "/ocs/v2.php/cloud/shares", ipPublique, ct, strings.NewReader(`{}`))
	ls := lignesDe(b.lignes(t), "nextcloud")
	if len(ls) != 1 || ls[0]["rule_id"] != "nc-002" || ls[0]["severity"] != "high" {
		t.Fatalf("6e appel : une ligne nc-002 high attendue, eu %v", ls)
	}
	if n := signalLigne(t, ls[0], "appels_federes"); n != 6 {
		t.Errorf("signals.appels_federes = %d, attendu 6", n)
	}
	b.requeteNC(http.MethodPost, "/ocs/v2.php/cloud/shares", "203.0.113.8", ct, strings.NewReader(`{}`))
	if ls := lignesDe(b.lignes(t), "nextcloud"); len(ls) != 1 {
		t.Errorf("autre IP, 1er appel : aucune ligne de plus attendue, eu %v", ls)
	}
	b.verifierSansSanction(t, ipPublique)
}

func TestNextcloudProxyAgenda(t *testing.T) {
	const chemin = "/remote.php/dav/principals/users/alice/calendar-proxy-write"
	corps := `<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:"/>`
	b := bancNextcloud(t, "")
	b.requeteNC("PROPPATCH", chemin, ipPublique, http.Header{"Authorization": {basic("alice:mot-de-passe-secret")}}, strings.NewReader(corps))
	ls := lignesDe(b.lignes(t), "nextcloud")
	if len(ls) != 1 || ls[0]["rule_id"] != "nc-003" || ls[0]["severity"] != "medium" {
		t.Fatalf("Basic alice : exactement une ligne nc-003 attendue, eu %v", ls)
	}
	b.requeteNC("PROPPATCH", chemin, ipPublique, http.Header{"Authorization": {basic("BOB:mot-de-passe-secret")}}, strings.NewReader(corps))
	ls = lignesDe(b.lignes(t), "nextcloud")
	if len(ls) != 2 || ls[1]["rule_id"] != "nc-004" || ls[1]["severity"] != "high" {
		t.Fatalf("Basic bob : exactement une ligne nc-004 de plus attendue, eu %v", ls)
	}
	// Sans casse : ALICE est alice.
	b.requeteNC("PROPPATCH", chemin, ipPublique, http.Header{"Authorization": {basic("ALICE:x")}}, strings.NewReader(corps))
	ls = lignesDe(b.lignes(t), "nextcloud")
	if len(ls) != 3 || ls[2]["rule_id"] != "nc-003" {
		t.Fatalf("Basic ALICE : une ligne nc-003 attendue, eu %v", ls)
	}
	// Ni l'uid, ni l'identifiant Basic, ni le mot de passe au journal.
	brut := strings.ToLower(b.journalBrut(t))
	for _, interdit := range []string{"alice", "bob", "mot-de-passe", "basic "} {
		if strings.Contains(brut, interdit) {
			t.Errorf("le journal contient %q : %s", interdit, brut)
		}
	}
	b.verifierSansSanction(t, ipPublique)
}

// corpsTaille : debut suivi de remplissage, len total n.
func corpsTaille(debut string, n int) []byte {
	return append([]byte(debut), contenuTexte(n-len(debut))...)
}

func TestNextcloudPutNonRaster(t *testing.T) {
	b := bancNextcloud(t, "")
	ct := http.Header{"Content-Type": {"application/octet-stream"}}
	corps := corpsTaille("%!PS-Adobe-3.0\n", 3<<20)
	if rec := b.requeteNC(http.MethodPut, "/remote.php/dav/files/alice/a.png", ipPublique, ct, bytes.NewReader(corps)); rec.Code != http.StatusOK {
		t.Fatalf("statut %d, attendu 200", rec.Code)
	}
	b.verifierRecu(t, corps)
	ls := lignesDe(b.lignes(t), "nextcloud")
	if len(ls) != 1 || ls[0]["rule_id"] != "nc-005" || ls[0]["severity"] != "medium" {
		t.Fatalf("une ligne nc-005 attendue, eu %v", b.lignes(t))
	}
	// Ni le nom de fichier ni l'uid au journal.
	if brut := b.journalBrut(t); strings.Contains(brut, "a.png") || strings.Contains(brut, "alice") {
		t.Errorf("le journal contient le nom de fichier ou l'uid : %s", brut)
	}
	png := corpsTaille("\x89PNG\r\n\x1a\n", 4096)
	b.requeteNC(http.MethodPut, "/remote.php/dav/files/alice/b.png", ipPublique, ct, bytes.NewReader(png))
	b.requeteNC(http.MethodPut, "/remote.php/dav/files/alice/doc.pdf", ipPublique, ct, strings.NewReader("%PDF-1.7\n"))
	if ls := lignesDe(b.lignes(t), "nextcloud"); len(ls) != 1 {
		t.Errorf("PNG réel ou PDF bien nommé : aucune ligne de plus attendue, eu %v", ls)
	}
	// Premier segment d'un envoi en segments : l'extension vient de Destination.
	seg := http.Header{"Content-Type": {"application/octet-stream"},
		"Destination": {"https://nc.example/remote.php/dav/files/alice/c.jpg"}}
	b.requeteNC(http.MethodPut, "/remote.php/dav/uploads/alice/web-file-upload-1/1", ipPublique, seg, strings.NewReader("<svg onload=1>"))
	b.requeteNC(http.MethodPut, "/remote.php/dav/uploads/alice/web-file-upload-1/2", ipPublique, seg, strings.NewReader("<svg onload=1>"))
	ls = lignesDe(b.lignes(t), "nextcloud")
	if len(ls) != 2 || ls[1]["rule_id"] != "nc-005" {
		t.Errorf("segments : une ligne nc-005 pour le 1er seulement, eu %v", ls)
	}
	b.verifierSansSanction(t, ipPublique)
}

// R-W2 (point 10) : le début d'un PUT se capture SANS jeton. Sémaphores pleins :
// la ligne nc-005 est écrite, aucune ligne de concurrence, aucun jeton pris.
func TestNextcloudPutSansJeton(t *testing.T) {
	b := bancNextcloud(t, "")
	b.s.capturesMultipart = make(chan struct{}, 1)
	b.s.capturesUrlencoded = make(chan struct{}, 1)
	b.s.capturesMultipart <- struct{}{}
	b.s.capturesUrlencoded <- struct{}{}
	corps := corpsTaille("%PDF-1.7\n", 1<<16)
	b.requeteNC(http.MethodPut, "/remote.php/dav/files/alice/a.jpg", ipPublique,
		http.Header{"Content-Type": {"image/jpeg"}}, bytes.NewReader(corps))
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	if d := lignesDe(ls, "nextcloud"); len(d) != 1 || d[0]["rule_id"] != "nc-005" {
		t.Errorf("une ligne nc-005 attendue, eu %v", ls)
	}
	for _, l := range ls {
		if c, _ := l["category"].(string); strings.Contains(c, "concurrence") {
			t.Errorf("ligne de concurrence inattendue : %v", l)
		}
	}
	if len(b.s.capturesMultipart) != 1 || len(b.s.capturesUrlencoded) != 1 {
		t.Errorf("jetons modifiés : %d multipart, %d urlencoded, attendu 1 et 1",
			len(b.s.capturesMultipart), len(b.s.capturesUrlencoded))
	}
}

func TestNextcloudTraficLegitimeMuet(t *testing.T) {
	b := bancNextcloud(t, "")
	propfind := `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>`
	b.requeteNC("PROPFIND", "/remote.php/dav/files/alice/", ipPublique,
		http.Header{"Content-Type": {"application/xml"}, "Depth": {"1"}, "Authorization": {basic("alice:pw")}},
		strings.NewReader(propfind))
	jpeg := corpsTaille("\xff\xd8\xff\xe0\x00\x10JFIF\x00", 8192)
	b.requeteNC(http.MethodPut, "/remote.php/dav/files/alice/vacances/photo.jpg", ipPublique,
		http.Header{"Content-Type": {"image/jpeg"}, "Authorization": {basic("alice:pw")}}, bytes.NewReader(jpeg))
	b.requeteNC(http.MethodGet, "/ocs/v2.php/cloud/user?format=json", ipPublique,
		http.Header{"Cookie": {"ocabcdef1234=s; oc_sessionPassphrase=p"}, "OCS-APIRequest": {"true"}}, nil)
	b.requeteNC(http.MethodPost, "/ocs/v2.php/cloud/shares", ipPublique,
		http.Header{"Content-Type": {"application/json"}, "Authorization": {basic("alice:pw")}, "OCS-APIRequest": {"true"}},
		strings.NewReader(`{"path":"/a","shareType":3}`))
	b.requeteNC("PROPPATCH", "/remote.php/dav/files/alice/a.txt", ipPublique,
		http.Header{"Authorization": {basic("alice:pw")}}, strings.NewReader(`<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:"/>`))
	if ls := b.lignes(t); len(ls) != 0 {
		t.Errorf("trafic légitime : aucune ligne attendue, eu %v", ls)
	}
}

// Les contrôles Nextcloud ne lisent pas la chaîne de requête : aucun n'est
// inscrit dans controlesRequete (la requête n'est lue que si utile).
func TestNextcloudControlesSansRequete(t *testing.T) {
	for c, p := range map[string]string{"nc_partage_federe": "", "nc_partage_federe_rafale": "appels_min",
		"nc_proxy_agenda": "", "nc_proxy_agenda_autrui": "", "nc_put_non_raster": ""} {
		if controlesRequete[c] {
			t.Errorf("%s ne lit pas la requête", c)
		}
		if got, ok := parametreRequis[c]; !ok || got != p {
			t.Errorf("parametreRequis[%s] = (%q, %v), attendu %q", c, got, ok, p)
		}
	}
	r := LoadRules(ecrisRegles(t, corpusNextcloudTest))
	if r.litLaRequete() {
		t.Error("le corpus Nextcloud seul ne doit pas faire lire la requête")
	}
}

// nouvelleEntreePHP remplit les champs Nextcloud ; corpsACapturer prend le
// début d'un PUT raster (64 octets au plus, sans jeton) ; completerCorps en
// tire MagiqueDebut.
func TestEntreeNextcloud(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(`{"services": {"nextcloud": {"legit_paths": []}},
		"vhosts": {"nc.example": "nextcloud"}, "php_services": ["nextcloud"], "federation_vhosts": ["nc.example"]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{vhostProfiles: vp}
	r := httptest.NewRequest("post", "http://nc.example/ocm/shares/", strings.NewReader("{}"))
	e := s.nouvelleEntreePHP(r, "nextcloud")
	if !e.PartageFedereAnonyme || !e.Federation {
		t.Errorf("POST anonyme /ocm/shares/ : %+v", e)
	}
	r.Header.Set("Cookie", "nc_token=x")
	if e = s.nouvelleEntreePHP(r, "nextcloud"); e.PartageFedereAnonyme {
		t.Errorf("avec session : PartageFedereAnonyme attendu faux")
	}

	r = httptest.NewRequest("PROPPATCH", "http://nc.example/remote.php/dav/principals/users/al%69ce/calendar-proxy-read", nil)
	if e = s.nouvelleEntreePHP(r, "nextcloud"); !e.ProxyAgenda || e.ProxyAgendaAutrui {
		t.Errorf("sans Basic : ProxyAgenda=%v Autrui=%v, attendu vrai/faux", e.ProxyAgenda, e.ProxyAgendaAutrui)
	}
	r.Header.Set("Authorization", basic("Alice:pw"))
	if e = s.nouvelleEntreePHP(r, "nextcloud"); !e.ProxyAgenda || e.ProxyAgendaAutrui {
		t.Errorf("Basic Alice, uid décodé alice : Autrui=%v, attendu faux", e.ProxyAgendaAutrui)
	}
	r.Header.Set("Authorization", basic("bob:pw"))
	if e = s.nouvelleEntreePHP(r, "nextcloud"); !e.ProxyAgendaAutrui {
		t.Errorf("Basic bob : Autrui attendu vrai")
	}

	r = httptest.NewRequest(http.MethodPut, "http://nc.example/remote.php/dav/files/alice/a.PNG", strings.NewReader("%!PS"))
	e = s.nouvelleEntreePHP(r, "nextcloud")
	if !e.PutRaster {
		t.Fatalf("PUT a.PNG : PutRaster attendu vrai")
	}
	g, p, j := s.corpsACapturer(r, e)
	if g != corpsDebut || p != magiqueOctets || j {
		t.Errorf("corpsACapturer = (%v, %d, %v), attendu (corpsDebut, 64, false)", g, p, j)
	}
	completerCorps(e, corpsDebut, []byte("%!PS-Adobe"), "", false)
	if e.MagiqueDebut != "ps" {
		t.Errorf("MagiqueDebut = %q, attendu ps", e.MagiqueDebut)
	}
	r = httptest.NewRequest(http.MethodPut, "http://nc.example/remote.php/dav/files/alice/a.pdf", strings.NewReader("%PDF-"))
	if e = s.nouvelleEntreePHP(r, "nextcloud"); e.PutRaster {
		t.Errorf("PUT a.pdf : PutRaster attendu faux")
	}
	if g, _, _ := s.corpsACapturer(r, e); g != corpsAucun {
		t.Errorf("PUT a.pdf : genre %v, attendu corpsAucun", g)
	}
	// Fenêtre plus petite que 64 : le plafond la suit.
	s.maxBodyInspect = 16
	r = httptest.NewRequest(http.MethodPut, "http://nc.example/remote.php/dav/files/alice/a.gif", strings.NewReader("x"))
	if _, p, _ := s.corpsACapturer(r, s.nouvelleEntreePHP(r, "nextcloud")); p != 16 {
		t.Errorf("plafond %d, attendu 16 (fenêtre)", p)
	}
}

// Le chemin journalisé d'une requête WebDAV ne porte ni uid ni nom de fichier.
func TestCheminJournalNextcloud(t *testing.T) {
	cas := []struct{ chemin, masque string }{
		{"/remote.php/dav/principals/users/alice/calendar-proxy-write", "/remote.php/dav/principals/users/*/calendar-proxy-write"},
		{"/remote.php/dav/principals/users/alice/calendar-proxy-read/", "/remote.php/dav/principals/users/*/calendar-proxy-read"},
		{"/remote.php/dav/principals/users/alice/", "/remote.php/dav/principals/users/*"},
		{"/remote.php/dav/files/alice/secret.png", "/remote.php/dav/files/*"},
		{"/remote.php/dav/uploads/alice/1/1", "/remote.php/dav/uploads/*"},
		{"/remote.php/webdav/secret.png", "/remote.php/webdav/*"},
	}
	for _, c := range cas {
		if m, ok := cheminJournalNextcloud(c.chemin); !ok || m != c.masque {
			t.Errorf("cheminJournalNextcloud(%q) = (%q, %v), attendu %q", c.chemin, m, ok, c.masque)
		}
	}
	if _, ok := cheminJournalNextcloud("/ocm/shares"); ok {
		t.Error("/ocm/shares : rien à masquer")
	}
}
