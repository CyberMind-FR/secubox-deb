package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
