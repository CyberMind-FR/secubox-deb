package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// La resolution passe par le demon parce que `connect-src` vaut 'self'.
// L'ouvrir laisserait la page appeler des origines tierces — sur une surface
// qui rend du contenu ecrit par des membres, c'est ce qu'on evite.
func TestFicheRefuseCeQuiNestPasNotre(t *testing.T) {
	s := &Server{opt: Options{MediaOrigines: []string{"https://peertube.gk2.secubox.in"}}}
	for _, u := range []string{
		"https://evil.example/w/x",
		"https://peertube.gk2.secubox.in.mal.tld/w/x",
		"http://peertube.gk2.secubox.in/w/x",
		"https://127.0.0.1:8001/openapi.json",
		"",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/media-fiche?u="+u, nil)
		s.servirMediaFiche(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("FUITE : %q a ete resolu", u)
		}
	}
}

// Une vignette distante doit repartir par NOTRE relais : la rendre telle quelle
// ferait charger l'image depuis le service par le navigateur du membre, et
// `img-src 'self'` la refuserait de toute facon.
func TestLaVignetteRepartParNotreRelais(t *testing.T) {
	got := vignetteRelayee("https://peertube.gk2.secubox.in/lazy-static/previews/abc.jpg")
	if !strings.HasPrefix(got, "/media-vignette?u=") {
		t.Fatalf("vignette non relayee : %s", got)
	}
	if strings.Contains(got, "://peertube") && !strings.Contains(got, "%3A%2F%2F") {
		t.Fatalf("adresse non encodee, elle sortirait du parametre : %s", got)
	}
	if vignetteRelayee("") != "" {
		t.Error("une vignette absente ne doit pas produire d'adresse")
	}
}
