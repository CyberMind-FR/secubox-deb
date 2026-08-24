package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func adm(t *testing.T, brut string, liste []string) bool {
	t.Helper()
	u, err := url.Parse(brut)
	if err != nil {
		return false
	}
	return origineAdmise(u, liste)
}

// La liste est ce qui empeche le demon de devenir un proxy ouvert : sans elle,
// une adresse quelconque postee par un membre permettrait de sonder
// l'agregateur ou un conteneur depuis le WAN, derriere l'adresse de la board.
func TestSeulesLesOriginesConfigureesPassent(t *testing.T) {
	liste := []string{"https://peertube.gk2.secubox.in", "https://radio.gk2.secubox.in/"}

	for _, bon := range []string{
		"https://peertube.gk2.secubox.in/vi/x.jpg",
		"https://RADIO.gk2.secubox.in/vignette/3",
	} {
		if !adm(t, bon, liste) {
			t.Errorf("origine configuree refusee : %s", bon)
		}
	}
	for _, mauvais := range []string{
		"http://peertube.gk2.secubox.in/x.jpg",       // pas https
		"https://evil.example/x.jpg",                 // hors liste
		"https://peertube.gk2.secubox.in.evil.tld/x", // suffixe trompeur
		"https://mal.peertube.gk2.secubox.in/x.jpg",  // sous-domaine
		"https://127.0.0.1:8001/openapi.json",        // service interne
		"https://10.100.0.180:8091/x",                // conteneur
		"",
	} {
		if adm(t, mauvais, liste) {
			t.Errorf("PROXY OUVERT : %s a ete accepte", mauvais)
		}
	}
}

// Sans configuration, on ne relaie rien : une autre installation n'a pas nos
// noms de vhost, et un defaut permissif y ouvrirait un relais silencieux.
func TestSansConfigurationAucunRelais(t *testing.T) {
	s := &Server{opt: Options{}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/media-vignette?u=https://peertube.gk2.secubox.in/x.jpg", nil)
	s.servirMediaVignette(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("un relais a repondu sans origine configuree")
	}
}

// Un `text/html` relaye serait servi depuis NOTRE origine, donc avec le droit
// d'executer du script dans notre politique.
func TestSeulesLesImagesSontRendues(t *testing.T) {
	for t2, ok := range map[string]bool{
		"image/png": true, "image/jpeg": true,
		"text/html": false, "application/javascript": false, "image/svg+xml": false,
	} {
		if mediaTypes[t2] != ok {
			t.Errorf("%s : admis=%v, attendu %v", t2, mediaTypes[t2], ok)
		}
	}
}

// Un ANONYME doit pouvoir obtenir une vignette : les pages publiques en
// affichent, et le garde-fou de ce relais est la liste blanche d'origines, pas
// la session. Le verrou « reserve aux membres » repondait 403 en invoquant le
// risque du proxy ouvert — risque que la liste blanche ecarte deja (cf.
// TestSeulesLesOriginesConfigureesPassent). Il ne protegeait rien et vidait de
// leurs images les pages vues sans compte.
func TestAnonymeObtientLaVignette(t *testing.T) {
	amont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("\x89PNG\r\n\x1a\n"))
	}))
	defer amont.Close()

	// L'amont de test est en http : on court-circuite la verification d'origine
	// en autorisant exactement son URL, et on verifie ici l'ABSENCE de verrou
	// de session, pas la liste blanche (testee separement).
	s := &Server{opt: Options{MediaOrigines: []string{amont.URL}}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/media-vignette?u="+url.QueryEscape(amont.URL+"/x.png"), nil)

	s.servirMediaVignette(rec, req) // aucun cookie de session : visiteur anonyme

	if rec.Code == http.StatusForbidden {
		t.Fatal("403 a un anonyme : le verrou membre est revenu")
	}
}

// La vignette relayee ne depend pas de qui regarde — aucun en-tete du visiteur
// n'est transmis en amont. La marquer `private` interdisait au cache partage de
// l'absorber, ce qui etait precisement le garde-fou contre l'amplification.
func TestVignetteCachableParUnCachePartage(t *testing.T) {
	amont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write([]byte("\xff\xd8\xff"))
	}))
	defer amont.Close()

	s := &Server{opt: Options{MediaOrigines: []string{amont.URL}}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/media-vignette?u="+url.QueryEscape(amont.URL+"/x.jpg"), nil)
	s.servirMediaVignette(rec, req)

	if cc := rec.Header().Get("Cache-Control"); cc != "" && !strings.HasPrefix(cc, "public") {
		t.Fatalf("Cache-Control = %q : un cache partage ne peut pas absorber la vignette", cc)
	}
}
