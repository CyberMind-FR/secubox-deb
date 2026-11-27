// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const defiHote = "gitea.exemple.test"

// Adresses de documentation (RFC 5737) : aucune adresse réelle.
const ipExt = "203.0.113.7"

const uaNav = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

type banCalculFaux struct {
	mu   sync.Mutex
	bans []time.Duration
	ips  []string
	fait chan struct{}
}

func (b *banCalculFaux) BanFor(ip, cat, sev string, d time.Duration) {
	b.mu.Lock()
	b.bans, b.ips = append(b.bans, d), append(b.ips, ip)
	b.mu.Unlock()
	b.fait <- struct{}{}
}

type robotsCalculFaux map[string]string

func (r robotsCalculFaux) Verifie(ip string) string { return r[ip] }

type journalCalculFaux struct {
	mu  sync.Mutex
	rec []ThreatRecord
}

func (j *journalCalculFaux) ajouter(r ThreatRecord) { j.mu.Lock(); j.rec = append(j.rec, r); j.mu.Unlock() }

func fichierDefi(t *testing.T, etat string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "defi-calcul.json")
	c := `{"difficulte_bits": 8, "duree_cookie": "6h", "insistance": {"seuil": 20, "fenetre": "10m", "durees": ["24h","168h"]},
	 "vhosts": {"` + defiHote + `": {"etat": "` + etat + `",
	   "chemins": ["^(/[^/]+/[^/]+)?/(src/commit|blame|raw|commits|compare|archive)(/|$)"],
	   "exclus": ["^/[^/]+/[^/]+/raw/branch/[^/]+/public/"]}}}`
	if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func nouveauDefi(t *testing.T, etat string) (*DefiCalcul, *banCalculFaux, *journalCalculFaux, *time.Time) {
	t.Helper()
	d := NewDefiCalcul(fichierDefi(t, etat), []byte("cle-de-test-cle-de-test-cle-de-test-0123"))
	horloge := time.Unix(1_800_000_000, 0)
	d.now = func() time.Time { return horloge }
	b := &banCalculFaux{fait: make(chan struct{}, 64)}
	j := &journalCalculFaux{}
	d.banneur, d.journal = b, j.ajouter
	d.robots = robotsCalculFaux{"198.51.100.9": "googlebot.com"}
	return d, b, j, &horloge
}

func requeteCalcul(method, chemin, ip, ua, accept string) *http.Request {
	r := httptest.NewRequest(method, "https://"+defiHote+chemin, nil)
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("User-Agent", ua)
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	return r
}

var reJeton = regexp.MustCompile(`data-t="([^"]+)" data-b="(\d+)" data-r="([^"]*)"`)

// resoudre fait en Go ce que fait la page.
func resoudreCalcul(tok string, bits int) string {
	for n := 0; ; n++ {
		if bitsNuls(sha256.Sum256([]byte(tok+":"+strconv.Itoa(n)))) >= bits {
			return strconv.Itoa(n)
		}
	}
}

func servirPage(t *testing.T, d *DefiCalcul, r *http.Request) (string, int) {
	t.Helper()
	w := httptest.NewRecorder()
	if !d.Intercepte(w, r, defiHote) {
		t.Fatalf("%s %s : défi attendu", r.Method, r.URL.Path)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP inattendue : %q", csp)
	}
	m := reJeton.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("jeton absent de la page")
	}
	bits, _ := strconv.Atoi(m[2])
	return m[1], bits
}

func poster(d *DefiCalcul, ip, ua string, champs url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://"+defiHote+cheminCalcul, strings.NewReader(champs.Encode()))
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	d.Intercepte(w, r, defiHote)
	return w
}

func cookieDe(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieCalcul {
			return c
		}
	}
	return nil
}

const cheminCommit = "/alice/projet/src/commit/0123abcd/README.md"

func TestDefiCalcul_EmissionVerificationCookie(t *testing.T) {
	d, _, _, horloge := nouveauDefi(t, "arme")
	tok, bits := servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	w := poster(d, ipExt, uaNav, url.Values{"t": {tok}, "n": {resoudreCalcul(tok, bits)}, "r": {cheminCommit}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != cheminCommit {
		t.Fatalf("solution valide : %d %q", w.Code, w.Header().Get("Location"))
	}
	ck := cookieDe(w)
	if ck == nil || !ck.HttpOnly || ck.Expires.Sub(*horloge) != 6*time.Hour {
		t.Fatalf("cookie attendu (HttpOnly, 6 h) : %+v", ck)
	}
	if strings.Contains(ck.Value, ipExt) {
		t.Fatal("le cookie ne doit pas porter l'adresse en clair")
	}
	r := requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html")
	r.AddCookie(ck)
	if d.Intercepte(httptest.NewRecorder(), r, defiHote) {
		t.Fatal("cookie valide : la requête doit passer")
	}
	// Même /24 (mobile, NAT) : le laissez-passer reste valable.
	r = requeteCalcul("GET", cheminCommit, "203.0.113.200", uaNav, "text/html")
	r.AddCookie(ck)
	if d.Intercepte(httptest.NewRecorder(), r, defiHote) {
		t.Fatal("même préfixe /24 : le cookie doit rester valable")
	}
	// Chemin non déclaré : jamais défié.
	if d.Intercepte(httptest.NewRecorder(), requeteCalcul("GET", "/alice/projet", ipExt, uaNav, "text/html"), defiHote) {
		t.Fatal("chemin non déclaré défié")
	}
}

func TestDefiCalcul_CookieFalsifieExpireRejoue(t *testing.T) {
	d, _, _, horloge := nouveauDefi(t, "arme")
	tok, bits := servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	nonce := resoudreCalcul(tok, bits)
	ck := cookieDe(poster(d, ipExt, uaNav, url.Values{"t": {tok}, "n": {nonce}, "r": {cheminCommit}}))
	cas := map[string]func(r *http.Request){
		"falsifié": func(r *http.Request) {
			p := strings.Split(ck.Value, ".")
			r.AddCookie(&http.Cookie{Name: cookieCalcul, Value: "1." + strconv.FormatInt(horloge.Add(48*time.Hour).Unix(), 10) + "." + p[2]})
		},
		"autre UA":     func(r *http.Request) { r.Header.Set("User-Agent", uaNav+" autre"); r.AddCookie(ck) },
		"autre réseau": func(r *http.Request) { r.RemoteAddr = "192.0.2.10:1"; r.AddCookie(ck) },
	}
	for nom, f := range cas {
		r := requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html")
		f(r)
		if !d.Intercepte(httptest.NewRecorder(), r, defiHote) {
			t.Errorf("cookie %s accepté", nom)
		}
	}
	// Expiré.
	*horloge = horloge.Add(6*time.Hour + time.Second)
	r := requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html")
	r.AddCookie(ck)
	if !d.Intercepte(httptest.NewRecorder(), r, defiHote) {
		t.Error("cookie expiré accepté")
	}
	// Jeton rejoué : usage unique.
	tok, bits = servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	nonce = resoudreCalcul(tok, bits)
	if cookieDe(poster(d, ipExt, uaNav, url.Values{"t": {tok}, "n": {nonce}})) == nil {
		t.Fatal("première solution refusée")
	}
	if cookieDe(poster(d, ipExt, uaNav, url.Values{"t": {tok}, "n": {nonce}})) != nil {
		t.Error("jeton rejoué accepté")
	}
	// Jeton d'un autre client, nonce faux, jeton périmé.
	c := d.config()
	tok, bits = servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	if got := d.verifierSolution(c, defiHote, "autre", tok, resoudreCalcul(tok, bits)); got != "signature" {
		t.Errorf("jeton d'un autre client : %q", got)
	}
	if got := d.verifierSolution(c, defiHote, d.empreinte(requeteCalcul("GET", "/", ipExt, uaNav, "")), tok, "x"); got != "calcul" && got != "" {
		t.Errorf("nonce faux : %q", got)
	}
	*horloge = horloge.Add(6 * time.Minute)
	if got := d.verifierSolution(c, defiHote, d.empreinte(requeteCalcul("GET", "/", ipExt, uaNav, "")), tok, resoudreCalcul(tok, bits)); got != "perime" {
		t.Errorf("jeton périmé : %q", got)
	}
}

func TestDefiCalcul_Exclusions(t *testing.T) {
	d, b, _, _ := nouveauDefi(t, "arme")
	cas := []struct {
		nom              string
		methode, chemin  string
		ip, ua, accept   string
		entete, valeurEn string
	}{
		{"git UA", "GET", cheminCommit, ipExt, "git/2.43.0", "text/html", "", ""},
		{"smart-http", "GET", "/alice/projet/info/refs", ipExt, uaNav, "text/html", "", ""},
		{"upload-pack", "GET", "/alice/projet/git-upload-pack", ipExt, uaNav, "text/html", "", ""},
		{"apt", "GET", "/alice/projet/raw/branch/main/x.deb", ipExt, "Debian APT-HTTP/1.3 (2.6.1)", "text/html", "", ""},
		{"agent secubox", "GET", cheminCommit, ipExt, "secubox-webos-hotes", "text/html", "", ""},
		{"api accept", "GET", cheminCommit, ipExt, uaNav, "application/json", "", ""},
		{"api chemin", "GET", "/api/v1/repos/alice/projet/commits", ipExt, uaNav, "text/html", "", ""},
		{"post", "POST", cheminCommit, ipExt, uaNav, "text/html", "", ""},
		{"webhook", "GET", cheminCommit, ipExt, uaNav, "text/html", "X-Gitea-Event", "push"},
		{"robot vérifié", "GET", cheminCommit, "198.51.100.9", "Mozilla/5.0 (compatible; Googlebot/2.1)", "text/html", "", ""},
		{"LAN", "GET", cheminCommit, "192.168.1.20", uaNav, "text/html", "", ""},
		{"maillage", "GET", cheminCommit, "10.10.0.5", uaNav, "text/html", "", ""},
		{"exclu déclaré", "GET", "/alice/projet/raw/branch/main/public/logo.png", ipExt, uaNav, "text/html", "", ""},
		{"image README", "GET", "/alice/projet/raw/branch/main/doc.png", ipExt, uaNav, "image/avif,image/*", "", ""},
	}
	for _, c := range cas {
		r := requeteCalcul(c.methode, c.chemin, c.ip, c.ua, c.accept)
		if c.entete != "" {
			r.Header.Set(c.entete, c.valeurEn)
		}
		for i := 0; i < 30; i++ { // au-delà du seuil : ni défi ni ban
			if d.Intercepte(httptest.NewRecorder(), r, defiHote) {
				t.Fatalf("%s : défié à tort", c.nom)
			}
		}
	}
	if len(b.bans) != 0 {
		t.Fatalf("exclus bannis : %v", b.ips)
	}
	// Un faux Googlebot (non vérifié) est défié.
	if !d.Intercepte(httptest.NewRecorder(), requeteCalcul("GET", cheminCommit, ipExt, "Googlebot/2.1", "text/html"), defiHote) {
		t.Error("robot non vérifié non défié")
	}
}

func TestDefiCalcul_DesarmeObserve(t *testing.T) {
	d, b, j, _ := nouveauDefi(t, "desarme")
	for i := 0; i < 30; i++ {
		if d.Intercepte(httptest.NewRecorder(), requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"), defiHote) {
			t.Fatal("désarmé : rien ne doit être servi")
		}
	}
	d, b, j, _ = nouveauDefi(t, "observe")
	for i := 0; i < 30; i++ {
		if d.Intercepte(httptest.NewRecorder(), requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"), defiHote) {
			t.Fatal("observe : rien ne doit être servi")
		}
	}
	if len(b.bans) != 0 || len(j.rec) != 1 || j.rec[0].Action != "propose" {
		t.Fatalf("observe : une ligne « propose », aucun ban ; bans=%v journal=%+v", b.bans, j.rec)
	}
}

func TestDefiCalcul_BanParInsistanceGradue(t *testing.T) {
	d, b, j, horloge := nouveauDefi(t, "arme")
	for i := 0; i < 19; i++ {
		servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	}
	if len(j.rec) != 0 {
		t.Fatal("ban avant le seuil")
	}
	servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	<-b.fait
	if b.bans[0] != 24*time.Hour || j.rec[0].Action != "banned" || j.rec[0].Category != categorieInsistance {
		t.Fatalf("1er ban 24 h attendu : %v %+v", b.bans, j.rec[0])
	}
	for i := 0; i < 10; i++ { // même fenêtre : un seul ban
		servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	}
	*horloge = horloge.Add(11 * time.Minute)
	for i := 0; i < 20; i++ {
		servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	}
	<-b.fait
	if len(b.bans) != 2 || b.bans[1] != 7*24*time.Hour {
		t.Fatalf("2e ban 7 j attendu : %v", b.bans)
	}
	// Qui résout repart de zéro.
	ip2 := "192.0.2.44"
	for i := 0; i < 19; i++ {
		servirPage(t, d, requeteCalcul("GET", cheminCommit, ip2, uaNav, "text/html"))
	}
	tok, bits := servirPage(t, d, requeteCalcul("GET", cheminCommit, ip2, uaNav, "text/html")) // 20e : ban
	<-b.fait
	_ = tok
	_ = bits
	ip3 := "192.0.2.45"
	for i := 0; i < 19; i++ {
		tok, bits = servirPage(t, d, requeteCalcul("GET", cheminCommit, ip3, uaNav, "text/html"))
	}
	poster(d, ip3, uaNav, url.Values{"t": {tok}, "n": {resoudreCalcul(tok, bits)}})
	for i := 0; i < 19; i++ {
		servirPage(t, d, requeteCalcul("GET", cheminCommit, ip3, uaNav, "text/html"))
	}
	if len(b.bans) != 3 {
		t.Fatalf("qui a résolu ne doit pas être banni : %v", b.ips)
	}
}

func TestDefiCalcul_InsistanceEpargne(t *testing.T) {
	d, b, j, _ := nouveauDefi(t, "arme")
	d.epargne = func(ip string) string { return "plage protégée" }
	for i := 0; i < 25; i++ {
		servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	}
	if len(b.bans) != 0 || len(j.rec) != 1 || j.rec[0].Action != "epargne" {
		t.Fatalf("épargnée : aucun ban, une ligne « epargne » ; bans=%v journal=%+v", b.bans, j.rec)
	}
}

func TestDefiCalcul_EmpreinteAutomatisationIndiceSansBan(t *testing.T) {
	d, b, j, _ := nouveauDefi(t, "arme")
	tok, bits := servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	w := poster(d, ipExt, uaNav, url.Values{"t": {tok}, "n": {resoudreCalcul(tok, bits)}, "e": {"webdriver,headless_ua,<script>,webdriver"}, "ms": {"42"}})
	if cookieDe(w) == nil {
		t.Fatal("l'indice ne doit pas empêcher le laissez-passer")
	}
	if len(j.rec) != 1 {
		t.Fatalf("une ligne d'indice attendue : %+v", j.rec)
	}
	x := j.rec[0]
	if x.Category != categorieIndice || x.Action != "detect" || x.Severity != "audit" ||
		strings.Join(x.Indice, ",") != "automatisation:webdriver,automatisation:headless_ua" || x.Signaux["resolution_ms"] != 42 {
		t.Fatalf("ligne d'indice inattendue : %+v", x)
	}
	if len(b.bans) != 0 {
		t.Fatal("un indice ne bannit jamais")
	}
	// Sans trait : aucune ligne.
	tok, bits = servirPage(t, d, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"))
	poster(d, ipExt, uaNav, url.Values{"t": {tok}, "n": {resoudreCalcul(tok, bits)}})
	if len(j.rec) != 1 {
		t.Fatal("solution sans indice journalisée")
	}
}

func TestDefiCalcul_IndiceDansJournal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "waf-threats.log")
	NewThreatLog(p).Record(ThreatRecord{ClientIP: ipExt, Host: defiHote, Category: categorieIndice, Action: "detect", Indice: []string{"automatisation:webdriver"}})
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"indice":["automatisation:webdriver"]`) {
		t.Fatalf("champ indice absent : %s", b)
	}
	env := entryToEnvelope(&logEntry{Category: categorieIndice, Indice: []string{"automatisation:webdriver"}})
	if !strings.Contains(strings.Join(env.BehaviorTags, ","), "automatisation:webdriver") {
		t.Fatalf("indice non versé à actord : %v", env.BehaviorTags)
	}
}

func TestDefiCalcul_ConfigInvalideGardeLaPrecedente(t *testing.T) {
	d, _, _, horloge := nouveauDefi(t, "arme")
	if err := os.WriteFile(d.chemin, []byte(`{"vhosts":{"x":{"etat":"arme","chemins":["("]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(d.chemin, future, future)
	*horloge = horloge.Add(10 * time.Second)
	if d.config().vhosts[defiHote] == nil {
		t.Fatal("config invalide : la précédente doit rester")
	}
	if _, err := compilerDefi([]byte(`{"difficulte_bits": 30}`)); err == nil {
		t.Error("difficulté excessive acceptée")
	}
}

func TestDefiCalcul_PageTailleEtCSP(t *testing.T) {
	d, _, _, _ := nouveauDefi(t, "arme")
	w := httptest.NewRecorder()
	d.Intercepte(w, requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html"), defiHote)
	n := w.Body.Len()
	t.Logf("taille de la page de défi : %d octets", n)
	if n > 6000 {
		t.Errorf("page trop lourde : %d octets", n)
	}
	if strings.Contains(w.Body.String(), "http://") || strings.Contains(w.Body.String(), "https://") || strings.Contains(w.Body.String(), "src=") {
		t.Error("la page ne doit charger aucune ressource externe")
	}
	if len(strings.Split(strings.Split(w.Body.String(), `data-t="`)[1], `"`)[0])+1+8 > 55 {
		t.Error("jeton + nonce doit tenir dans un bloc SHA-256")
	}
}

func BenchmarkDefiCalcul_Emission(b *testing.B) {
	d := NewDefiCalcul(filepath.Join(b.TempDir(), "absent.json"), []byte("cle-de-test-cle-de-test-cle-de-test-0123"))
	c := defiDefauts()
	r := requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.servir(httptest.NewRecorder(), r, c, defiHote)
	}
}

func BenchmarkDefiCalcul_Verification(b *testing.B) {
	d := NewDefiCalcul(filepath.Join(b.TempDir(), "absent.json"), []byte("cle-de-test-cle-de-test-cle-de-test-0123"))
	c := defiDefauts()
	c.validite = time.Hour
	r := requeteCalcul("GET", "/", ipExt, uaNav, "")
	fp := d.empreinte(r)
	toks := make([]string, b.N)
	nonces := make([]string, b.N)
	for i := range toks {
		toks[i] = d.jeton(defiHote, fp, 4)
		nonces[i] = resoudreCalcul(toks[i], 4)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%100000 == 0 {
			d.utilises = map[string]int64{} // la mémoire d'usage unique est bornée en production aussi
		}
		d.empreinte(r)
		if x := d.verifierSolution(c, defiHote, fp, toks[i], nonces[i]); x != "" && x != "rejoue" {
			b.Fatal(x)
		}
	}
}

func BenchmarkDefiCalcul_Cookie(b *testing.B) {
	d := NewDefiCalcul(filepath.Join(b.TempDir(), "absent.json"), []byte("cle-de-test-cle-de-test-cle-de-test-0123"))
	r := requeteCalcul("GET", cheminCommit, ipExt, uaNav, "text/html")
	r.AddCookie(&http.Cookie{Name: cookieCalcul, Value: d.valeurCookie(defiHote, d.empreinte(r), time.Now().Add(time.Hour).Unix())})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !d.CookieValide(r, defiHote) {
			b.Fatal("cookie refusé")
		}
	}
}
