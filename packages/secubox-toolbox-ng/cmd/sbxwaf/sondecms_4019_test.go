// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #4019 : chemins par défaut d'un CMS sur un vhost qui ne l'héberge pas = sonde, ban dès la 1re requête, gradué
// comme un leurre (24 h puis 7 j), sauf sur un vhost déclaré (cms_vhosts) ; jamais le LAN ni une plage protégée.

// Le corpus livré : les chemins de sonde touchent leur catégorie, ancrés au début du chemin.
func TestSondeCMS_CorpusAncre4019(t *testing.T) {
	r := LoadRules(corpusLivre)
	touche := []struct{ chemin, requete, cat string }{
		{"/wp-login.php", "", "cms_wordpress"},
		{"//xmlrpc.php", "rsd", "cms_wordpress"},
		{"/blog/wp-login.php", "", "cms_wordpress"},
		{"/wordpress/wp-includes/wlwmanifest.xml", "", "cms_wordpress"},
		{"/wp-json/batch/v1", "", "cms_wordpress"},
		{"/index.php/wp-json/wp/v2/users", "", "cms_wordpress"},
		{"/", "rest_route=/batch/v1", "cms_wordpress"},
		{"/wp-admin", "", "cms_wordpress"},
		{"/core/CHANGELOG.txt", "", "cms_drupal"},
		{"/sites/default/settings.php", "", "cms_drupal"},
		{"/administrator/", "", "cms_joomla"},
		{"/components/com_users/", "", "cms_joomla"},
		{"/index.php", "option=com_users", "cms_joomla"},
		{"/.DS_Store", "", "cms_defauts_web"},
		{"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", "cms_defauts_web"},
		{"/cgi-bin/", "", "cms_defauts_web"},
	}
	for _, c := range touche {
		cat, _, mode, _, hit := r.MatchDetail("GET", c.chemin, c.requete, "", "Mozilla/5.0", false, nil)
		if !hit || cat != c.cat || mode != modeEscalate {
			t.Errorf("%s?%s : cat=%q mode=%q hit=%v, attendu %s", c.chemin, c.requete, cat, mode, hit, c.cat)
		}
	}
	for cat, cms := range map[string]string{"cms_wordpress": "wordpress", "cms_drupal": "drupal", "cms_joomla": "joomla", "cms_defauts_web": "web"} {
		if r.SondeCMS(cat) != cms {
			t.Errorf("%s : sonde_cms=%q, attendu %q", cat, r.SondeCMS(cat), cms)
		}
		if seuil, _ := r.ParamsBan(cat); seuil != 1 {
			t.Errorf("%s : ban_seuil=%d, attendu 1", cat, seuil)
		}
	}
	if r.SondeCMS("scanners") != "" {
		t.Error("une catégorie ordinaire n'est pas une sonde de CMS")
	}
}

// Chemins non ancrés, segments voisins, corps et UA : jamais une sonde de CMS.
func TestSondeCMS_NonAncreLibre4019(t *testing.T) {
	r := LoadRules(corpusLivre)
	cas := []struct{ chemin, requete, corps, ua string }{
		{"/blog/", "", "", "Mozilla/5.0"},
		{"/blog/2026/11/un-billet", "", "", "Mozilla/5.0"},
		{"/user/login", "", "", "Mozilla/5.0"}, // Gitea : /user/login n'est pas une sonde Drupal
		{"/api/v1/metanews/img", "u=https://exemple.org/wp-content/uploads/a.jpg", "", "Mozilla/5.0"},
		{"/gandalf/depot/src/branch/main/wp-content/plugins/x.php", "", "", "Mozilla/5.0"},
		{"/docs/administrator-guide", "", "", "Mozilla/5.0"},
		{"/wp-login.php.txt", "", "", "Mozilla/5.0"},
		{"/notes", "", "voir /wp-admin/ et /administrator/", "Mozilla/5.0"},
		{"/", "", "", "WordPress/6.5; https://exemple.org/wp-json/"},
	}
	cms := r.CategoriesSondeCMS()
	for _, c := range cas {
		cat, _, _, _, hit := r.MatchDetail("POST", c.chemin, c.requete, c.corps, c.ua, true, nil)
		if hit && cms[cat] {
			t.Errorf("%s?%s [%s|%s] pris pour une sonde %s", c.chemin, c.requete, c.corps, c.ua, cat)
		}
	}
}

const reglesSondeCMS = `{
 "ia_test": {"name":"IA","severity":"critical","mode":"escalate","ban_seuil":1,"ban_duree":"168h",
   "patterns":[{"id":"ia-cve-x","pattern":"/wp-admin/admin-ajax\\.php","desc":"CVE précise"}]},
 "cms_wordpress": {"name":"WP","severity":"high","mode":"escalate","ban_seuil":1,"ban_duree":"24h","sonde_cms":"wordpress",
   "patterns":[{"id":"cms-wp-001","pattern":"(?:^|/\\.\\.)[/.]*(?:[a-z0-9_-]+/+)?wp-(?:login\\.php|admin)(?:$|[\\s?#/])","desc":"WP"}]}
}`

// serveurSondeCMS : cms_wordpress + un filtre IA plus précis, blog.example.com déclaré WordPress.
func serveurSondeCMS(t *testing.T) (*Server, *fauxNft, string) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(backend.Close)
	s := newDetectTestServer(t, backend.URL, writeRulesFile(t, reglesSondeCMS))
	s.escalateBan = NewBan(24*time.Hour, 3)
	vp, err := chargerVhostProfilesDepuis([]byte(`{"services":{},"vhosts":{},"cms_vhosts":{"Blog.Example.com":["WordPress"]}}`))
	if err != nil {
		t.Fatalf("profils : %v", err)
	}
	s.vhostProfiles = vp
	journal := filepath.Join(t.TempDir(), "waf-threats.log")
	s.threatLog = NewThreatLog(journal)
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	if err := b.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	s.nftBan = b
	return s, fx, journal
}

func requeteSonde(hote, chemin, ip string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://"+hote+chemin, nil)
	req.Host = hote
	req.RemoteAddr = ip + ":12345"
	return req
}

func journalContient(t *testing.T, chemin string, morceaux ...string) bool {
	t.Helper()
	for i := 0; i < 50; i++ {
		brut, _ := os.ReadFile(chemin)
		tout := true
		for _, m := range morceaux {
			tout = tout && strings.Contains(string(brut), m)
		}
		if tout {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func TestSondeCMS_Ban24hPuisRecidive7j4019(t *testing.T) {
	s, fx, journal := serveurSondeCMS(t)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, requeteSonde("www.example.com", "/wp-login.php", "203.0.113.10"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("1re sonde : %d, attendu 403", rec.Code)
	}
	if a := ajoutsNft(fx, 1); len(a) != 1 || !strings.Contains(a[0], "timeout 86400s") {
		t.Fatalf("ban attendu de 24 h (86400s), obtenu %v", a)
	}
	if !journalContient(t, journal, `"category":"cms_sonde:wordpress"`, `"action":"banned"`, `"rule_id":"cms-wp-001"`) {
		t.Fatal("journal des menaces sans la catégorie cms_sonde:wordpress")
	}
	if r, ok := s.nftBan.store.Actif("203.0.113.10", time.Now().Unix()); !ok || r.Category != "cms_sonde:wordpress" {
		t.Fatalf("ban enregistré sous %q, attendu cms_sonde:wordpress", r.Category)
	}

	// Récidive : un ban de sonde de CMS échu il y a 2 jours → 7 jours.
	s2, fx2, _ := serveurSondeCMS(t)
	_ = s2.nftBan.store.Append(BanRecord{IP: "203.0.113.11", Category: "cms_sonde:drupal", Severity: "high",
		At: time.Now().Add(-48 * time.Hour).Unix(), Expires: time.Now().Add(-24 * time.Hour).Unix(), Action: "ban"})
	s2.handler().ServeHTTP(httptest.NewRecorder(), requeteSonde("www.example.com", "/blog/wp-admin/", "203.0.113.11"))
	if a := ajoutsNft(fx2, 1); len(a) != 1 || !strings.Contains(a[0], "timeout 604800s") {
		t.Fatalf("récidive : ban attendu de 7 j (604800s), obtenu %v", a)
	}
}

func TestSondeCMS_VhostDeclareJamaisBanni4019(t *testing.T) {
	s, fx, journal := serveurSondeCMS(t)
	for _, hote := range []string{"blog.example.com", "BLOG.example.com:443"} {
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, requeteSonde(hote, "/wp-login.php", "203.0.113.20"))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s déclaré WordPress : %d, attendu 200", hote, rec.Code)
		}
	}
	// La garde anti-contrebande tient : une règle plus précise touche toujours, même sur le vhost déclaré.
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, requeteSonde("blog.example.com", "/wp-admin/admin-ajax.php", "203.0.113.21"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("filtre IA sur vhost déclaré : %d, attendu 403", rec.Code)
	}
	if a := ajoutsNft(fx, 1); len(a) != 1 || !strings.Contains(a[0], "203.0.113.21") {
		t.Fatalf("seul le filtre IA bannit, obtenu %v", a)
	}
	if !journalContient(t, journal, `"category":"ia_test"`) {
		t.Fatal("journal sans le filtre IA")
	}
	if brut, _ := os.ReadFile(journal); strings.Contains(string(brut), "cms_sonde") {
		t.Fatal("un vhost déclaré WordPress ne journalise pas de sonde WordPress")
	}
}

// Sur un vhost sans WordPress, la règle plus précise (CVE) nomme le ban plutôt que la catégorie générique.
func TestSondeCMS_ReglePrecisePrioritaire4019(t *testing.T) {
	s, fx, journal := serveurSondeCMS(t)
	s.handler().ServeHTTP(httptest.NewRecorder(), requeteSonde("www.example.com", "/wp-admin/admin-ajax.php", "203.0.113.30"))
	if a := ajoutsNft(fx, 1); len(a) != 1 || !strings.Contains(a[0], "timeout 604800s") {
		t.Fatalf("ban du filtre IA (168 h) attendu, obtenu %v", a)
	}
	if !journalContient(t, journal, `"category":"ia_test"`, `"rule_id":"ia-cve-x"`) {
		t.Fatal("le filtre IA ne nomme pas le ban")
	}
}

func TestSondeCMS_LANEtPlagesProtegeesEpargnes4019(t *testing.T) {
	s, fx, journal := serveurSondeCMS(t)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, requeteSonde("www.example.com", "/wp-login.php", "192.168.1.20"))
	if rec.Code != http.StatusOK {
		t.Fatalf("LAN : %d, attendu 200 (jamais inspecté)", rec.Code)
	}
	s.nftBan.protegees = parseCIDRs("198.51.100.0/24")
	s.handler().ServeHTTP(httptest.NewRecorder(), requeteSonde("www.example.com", "/wp-login.php", "198.51.100.7"))
	if !journalContient(t, journal, `"category":"cms_sonde:wordpress"`, `"action":"epargne"`) {
		t.Fatal("plage protégée : le journal doit écrire « epargne »")
	}
	if a := ajoutsNft(fx, 0); len(a) != 0 {
		t.Fatalf("aucun ban attendu (LAN, plage protégée), obtenu %v", a)
	}
}
