// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Bibliothèque figée OWASP CRS / Nuclei (#4020).

const bibTest = `{"bib_sondes_techno":{"name":"Bib","severity":"low","mode":"detect","bibliotheque":true,
	"patterns":[
	 {"id":"bib-nuclei-wp-1","pattern":"^/wp-content/plugins/akismet/readme\\.txt$","champ":"chemin","famille":"sondes_techno","techno":"wordpress"},
	 {"id":"bib-crs-913100-ua","pattern":"(?:nikto|sqlmap)","champ":"ua","famille":"ua_outils","techno":"generique"},
	 {"id":"bib-crs-930130-chemin","pattern":"(?:\\.git/config)","champ":"chemin","famille":"fichiers_exposes","techno":"git"}]}}`

func TestBib_LitteralExact(t *testing.T) {
	for motif, attendu := range map[string]string{
		`^/wp-login\.php$`: "/wp-login.php",
		`^/Admin/Index$`:   "/admin/index",
		`^/a-b_c~d$`:       "/a-b_c~d",
	} {
		if lit, ok := litteralExact(motif); !ok || lit != attendu {
			t.Errorf("%s : %q %v, attendu %q", motif, lit, ok, attendu)
		}
	}
	for _, motif := range []string{`/wp-login\.php$`, `^/wp-login\.php`, `^/a(b|c)$`, `^/a.b$`, `^/a+$`, `x`} {
		if _, ok := litteralExact(motif); ok {
			t.Errorf("%s : pris pour un littéral exact", motif)
		}
	}
}

func TestBib_ChampEtTableExacte(t *testing.T) {
	r := LoadRules(writeRulesFile(t, bibTest))
	cas := []struct {
		chemin, ua, id string
	}{
		{"/wp-content/plugins/akismet/readme.txt", "Mozilla/5.0", "bib-nuclei-wp-1"},
		{"/WP-CONTENT/plugins/akismet/readme.txt", "Mozilla/5.0", "bib-nuclei-wp-1"},
		{"/x/wp-content/plugins/akismet/readme.txt", "Mozilla/5.0", ""}, // exact : pas de sous-chaîne
		{"/", "Mozilla/5.0 sqlmap/1.7", "bib-crs-913100-ua"},
		{"/nikto", "Mozilla/5.0", ""}, // motif d'UA : le chemin n'est pas lu
		{"/depot/.git/config", "curl/8", "bib-crs-930130-chemin"},
		{"/ok", "curl/8 .git/config", ""}, // motif de chemin : l'UA n'est pas lue
	}
	for _, c := range cas {
		_, _, mode, id, hit := r.MatchDetail("GET", c.chemin, "", "", c.ua, true, nil)
		if (c.id == "") == hit || id != c.id {
			t.Errorf("%s / %s : hit=%v id=%q, attendu %q", c.chemin, c.ua, hit, id, c.id)
		}
		if hit && mode != modeDetect {
			t.Errorf("%s : mode %q, attendu detect", c.chemin, mode)
		}
	}
	et, techno, ok := r.InfoBibliotheque("bib_sondes_techno", "bib-nuclei-wp-1")
	if !ok || et != "bib:sondes_techno:wordpress" || techno != "wordpress" {
		t.Fatalf("étiquette %q %q %v", et, techno, ok)
	}
	if _, _, ok := r.InfoBibliotheque("bib_sondes_techno", "inconnu"); ok {
		t.Fatal("motif inconnu étiqueté")
	}
}

func TestBib_ChampInconnuRejeteNommement(t *testing.T) {
	r := LoadRules(writeRulesFile(t, `{"bib_x":{"bibliotheque":true,"patterns":[{"id":"bib-1","pattern":"a","champ":"cookie"}]}}`))
	_, _, rejetes, _ := r.Integrite()
	if len(rejetes) != 1 || rejetes[0] != "bib_x/bib-1" {
		t.Fatalf("rejetés : %v", rejetes)
	}
}

// Les motifs existants (sans champ) gardent le texte joint : non-régression.
func TestBib_SansChampTexteJointInchange(t *testing.T) {
	r := LoadRules(writeRulesFile(t, `{"scanners":{"patterns":[{"id":"s1","pattern":"^/x   sqlmap$"}]}}`))
	if _, _, _, _, hit := r.MatchDetail("GET", "/x", "", "", "SQLMAP", true, nil); !hit {
		t.Fatal("le texte joint chemin+ua n'est plus lu")
	}
}

// serveurBib : sbxwaf avec la bibliothèque en mode detect, banneur nft factice.
func serveurBib(t *testing.T, profils string) (http.Handler, *fauxNft, *Server, string) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(backend.Close)
	s := newDetectTestServer(t, backend.URL, writeRulesFile(t, bibTest))
	s.escalateBan = NewBan(24*time.Hour, 1)
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	if err := b.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	s.nftBan = b
	journal := filepath.Join(t.TempDir(), "threats.jsonl")
	s.threatLog = NewThreatLog(journal)
	if profils != "" {
		v, err := chargerVhostProfilesDepuis([]byte(profils))
		if err != nil {
			t.Fatalf("profils : %v", err)
		}
		s.vhostProfiles = v
	}
	return s.handler(), fx, s, journal
}

func reqBib(hote, chemin string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+hote+chemin, nil)
	r.Host = hote
	r.RemoteAddr = "203.0.113.90:4000"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	return r
}

// Identifier seulement : la touche passe, est étiquetée, et la pose de ban n'est JAMAIS appelée.
func TestBib_IdentifierSeulementNeBannitJamais(t *testing.T) {
	h, fx, s, journal := serveurBib(t, "")
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, reqBib("site.example.com", "/wp-content/plugins/akismet/readme.txt"))
		if rec.Code == http.StatusForbidden {
			t.Fatalf("touche %d bloquée en identifier seulement", i)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(ajoutsNft(fx, 0)); n != 0 {
		t.Fatalf("pose de ban appelée %d fois", n)
	}
	if s.ban.Count("203.0.113.90") != 0 || s.escalateBan.Count("203.0.113.90") != 0 {
		t.Fatal("compteur de ban incrémenté")
	}
	brut, _ := os.ReadFile(journal)
	if !strings.Contains(string(brut), `"category":"bib:sondes_techno:wordpress"`) {
		t.Fatalf("étiquette absente du journal : %s", brut)
	}
}

// Bannir est un choix par famille : la même famille en escalate bannit.
func TestBib_BannirParFamille(t *testing.T) {
	h, fx, s, journal := serveurBib(t, "")
	s.rules = LoadRules(writeRulesFile(t, strings.Replace(bibTest, `"mode":"detect"`, `"mode":"escalate","ban_seuil":1`, 1)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqBib("site.example.com", "/depot/.git/config"))
	if rec.Code != http.StatusForbidden || len(ajoutsNft(fx, 1)) != 1 {
		t.Fatalf("escalate seuil 1 : code %d", rec.Code)
	}
	brut, _ := os.ReadFile(journal)
	if !strings.Contains(string(brut), `"category":"bib:fichiers_exposes:git"`) {
		t.Fatalf("étiquette absente : %s", brut)
	}
}

// Un vhost qui héberge la techno visée n'est jamais touché (repli #4019 : service du vhost).
func TestBib_VhostHebergeantLaTechno(t *testing.T) {
	profils := `{"services":{"wordpress":{"legit_paths":[]}},"vhosts":{"blog.example.com":"wordpress"}}`
	h, _, _, journal := serveurBib(t, profils)
	h.ServeHTTP(httptest.NewRecorder(), reqBib("blog.example.com", "/wp-content/plugins/akismet/readme.txt"))
	if brut, _ := os.ReadFile(journal); strings.Contains(string(brut), "bib:") {
		t.Fatalf("touche sur le vhost qui héberge wordpress : %s", brut)
	}
	h.ServeHTTP(httptest.NewRecorder(), reqBib("autre.example.com", "/wp-content/plugins/akismet/readme.txt"))
	if brut, _ := os.ReadFile(journal); !strings.Contains(string(brut), "bib:sondes_techno:wordpress") {
		t.Fatalf("vhost sans wordpress : touche attendue, journal %s", brut)
	}
	// Déclaration par vhost des CMS hébergés (#4019, cms_vhosts).
	h, _, _, journal = serveurBib(t, `{"cms_vhosts":{"site.example.org":["wordpress"]}}`)
	h.ServeHTTP(httptest.NewRecorder(), reqBib("site.example.org", "/wp-content/plugins/akismet/readme.txt"))
	if brut, _ := os.ReadFile(journal); strings.Contains(string(brut), "bib:") {
		t.Fatalf("touche sur un vhost déclaré wordpress (cms_vhosts) : %s", brut)
	}
	var v *VhostProfiles
	if v.hebergeTechno("x", "wordpress") {
		t.Fatal("aucun profil : rien n'est hébergé")
	}
}

// ── bibliothèque livrée ─────────────────────────────────────────────────────────────────────────────

func cheminBibLivree() string {
	return filepath.Join("..", "..", "..", "secubox-waf-ng", "composants", "waf", "config", "bibliotheque", "categories.json")
}

func cheminReglesLivrees() string {
	return filepath.Join("..", "..", "..", "secubox-waf-ng", "composants", "waf", "config", "waf-rules.json")
}

// reglesAvecBib : waf-rules.json livré, suivi des catégories de la bibliothèque (ce que fait waf-rules-sync).
func reglesAvecBib(t testing.TB, avecBib bool) string {
	t.Helper()
	var livre map[string]json.RawMessage
	brut, err := os.ReadFile(cheminReglesLivrees())
	if err != nil {
		t.Skipf("règles livrées absentes : %v", err)
	}
	if err := json.Unmarshal(brut, &livre); err != nil {
		t.Fatal(err)
	}
	cats := strings.TrimSuffix(strings.TrimSpace(string(livre["categories"])), "}")
	if avecBib {
		var bib struct {
			Categories map[string]json.RawMessage `json:"categories"`
		}
		b, err := os.ReadFile(cheminBibLivree())
		if err != nil {
			t.Skipf("bibliothèque absente : %v", err)
		}
		if err := json.Unmarshal(b, &bib); err != nil {
			t.Fatal(err)
		}
		for nom, c := range bib.Categories {
			cats += fmt.Sprintf(",%q:%s", nom, c)
		}
	}
	p := filepath.Join(t.TempDir(), "waf-rules.json")
	if err := os.WriteFile(p, []byte(`{"categories":`+cats+`}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

var reIP = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func TestBib_LivreeChargeSansRejetNiAdresse(t *testing.T) {
	r := LoadRules(reglesAvecBib(t, true))
	declares, charges, rejetes, _ := r.Integrite()
	if len(rejetes) != 0 || declares != charges {
		t.Fatalf("%d déclarés, %d chargés, rejetés %v", declares, charges, rejetes)
	}
	brut, _ := os.ReadFile(cheminBibLivree())
	if ip := reIP.FindString(string(brut)); ip != "" {
		t.Fatalf("adresse IPv4 dans la bibliothèque livrée : %s", ip)
	}
	var bib struct {
		Categories map[string]struct {
			Mode         string `json:"mode"`
			Bibliotheque bool   `json:"bibliotheque"`
		} `json:"categories"`
	}
	_ = json.Unmarshal(brut, &bib)
	for nom, c := range bib.Categories {
		if c.Mode != modeDetect || !c.Bibliotheque || !strings.HasPrefix(nom, "bib_") {
			t.Errorf("%s : mode %q bibliotheque %v (detect et true attendus)", nom, c.Mode, c.Bibliotheque)
		}
	}
}

// Requêtes d'échantillon (forme du trafic réel : pages, API, statiques, quelques sondes).
var echantillonBench = []struct{ m, chemin, requete, ua string }{
	{"GET", "/", "", "Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0"},
	{"GET", "/api/v1/hub/status", "", "python-httpx/0.28.1"},
	{"GET", "/static/css/app.3f2a.css", "", "Mozilla/5.0 (iPhone) Safari/605.1"},
	{"GET", "/canal/v1/requetes", "attente=25", "Go-http-client/1.1"},
	{"POST", "/api/v1/auth/login", "", "Mozilla/5.0 Chrome/131.0"},
	{"GET", "/user/repo/src/commit/abcdef0123", "", "Mozilla/5.0 Chrome/131.0"},
	{"GET", "/index.php/apps/files/", "dir=/Photos&fileid=1234", "Mozilla/5.0 Firefox/133.0"},
	{"GET", "/.env", "", "Mozilla/5.0 zgrab/0.x"},
	{"GET", "/wp-login.php", "", "Mozilla/5.0"},
	{"GET", "/search", "q=recette+de+cuisine&page=2", "Mozilla/5.0 Chrome/131.0"},
}

func benchRegles(b *testing.B, avecBib bool) {
	r := LoadRules(reglesAvecBib(b, avecBib))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := echantillonBench[i%len(echantillonBench)]
		r.MatchDetail(e.m, e.chemin, e.requete, "", e.ua, true, nil)
	}
}

func BenchmarkMatch_SansBibliotheque(b *testing.B) { benchRegles(b, false) }
func BenchmarkMatch_AvecBibliotheque(b *testing.B) { benchRegles(b, true) }

// Mémoire tenue par les règles compilées (rapportée en octets de tas vivant).
func BenchmarkCharge_Memoire(b *testing.B) {
	for _, avec := range []bool{false, true} {
		p := reglesAvecBib(b, avec)
		b.Run(fmt.Sprintf("bib=%v", avec), func(b *testing.B) {
			var garde []*Rules
			for i := 0; i < b.N; i++ {
				runtime.GC()
				var m0, m1 runtime.MemStats
				runtime.ReadMemStats(&m0)
				r := LoadRules(p)
				runtime.GC()
				runtime.ReadMemStats(&m1)
				garde = append(garde, r)
				b.ReportMetric(float64(m1.HeapAlloc-m0.HeapAlloc), "octets-tas")
			}
			_ = garde
		})
	}
}

// Pire cas : une UA neuve à chaque requête (le mémo ne sert à rien, et se vide en étant plein).
func BenchmarkMatch_AvecBibliothequeUANeuves(b *testing.B) {
	r := LoadRules(reglesAvecBib(b, true))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := echantillonBench[i%len(echantillonBench)]
		r.MatchDetail(e.m, e.chemin, e.requete, "", fmt.Sprintf("%s r%d", e.ua, i), true, nil)
	}
}

func TestBib_MemoUABorneEtExact(t *testing.T) {
	m := nouveauMemoUA()
	motifs := []*regexp.Regexp{regexp.MustCompile("nikto"), regexp.MustCompile("sqlmap")}
	if v := m.verdicts("x sqlmap", motifs); v != 2 {
		t.Fatalf("verdicts %b", v)
	}
	if v := m.verdicts("x sqlmap", motifs); v != 2 {
		t.Fatalf("verdicts mémoïsés %b", v)
	}
	for i := 0; i < memoUAMax+10; i++ {
		m.verdicts(fmt.Sprintf("ua-%d", i), motifs)
	}
	if len(m.m) > memoUAMax {
		t.Fatalf("mémo non borné : %d", len(m.m))
	}
}

// Surcoût de la bibliothèque, mesuré EN ALTERNANCE (tranches de 500 requêtes) pour que la charge de la
// machine pèse pareil sur les deux jeux de règles. Métriques : ns par requête sans et avec, surcoût en %.
func BenchmarkMatch_Surcout(b *testing.B) {
	sans, avec := LoadRules(reglesAvecBib(b, false)), LoadRules(reglesAvecBib(b, true))
	var dSans, dAvec time.Duration
	n := 0
	b.ResetTimer()
	for n < b.N {
		for _, r := range []*Rules{sans, avec} {
			t0 := time.Now()
			for i := 0; i < 500; i++ {
				e := echantillonBench[(n+i)%len(echantillonBench)]
				r.MatchDetail(e.m, e.chemin, e.requete, "", e.ua, true, nil)
			}
			if r == sans {
				dSans += time.Since(t0)
			} else {
				dAvec += time.Since(t0)
			}
		}
		n += 500
	}
	b.ReportMetric(float64(dSans.Nanoseconds())/float64(n), "ns-sans")
	b.ReportMetric(float64(dAvec.Nanoseconds())/float64(n), "ns-avec")
	b.ReportMetric(100*float64(dAvec-dSans)/float64(dSans), "surcout-%")
}
