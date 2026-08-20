package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/connectors"
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

// TestFicheYoutubeCourtCircuiteOrigineAdmise verrouille le cablage de la
// Tache 8 : YouTube n'est PAS dans MediaOrigines (ce n'est pas un de NOS
// services), donc sans le court-circuit explicite avant origineAdmise, la
// requete tomberait a plat sur un 404 plutot que de rendre l'embed souverain.
func TestFicheYoutubeCourtCircuiteOrigineAdmise(t *testing.T) {
	ytsas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"video_id":"dQw4w9WgXcQ","state":"pending"}`))
	}))
	t.Cleanup(ytsas.Close)

	srv, s := banc(t)
	uid, _ := peuple(t, s)
	jeton, _ := s.NewSession(uid, "", "")
	srv.youtube = connectors.NouveauYouTube(
		&connectors.ClientYtsas{Base: ytsas.URL, HTTP: http.DefaultClient}, "gk2")

	req := httptest.NewRequest(http.MethodGet, "/media-fiche?u="+
		url.QueryEscape("https://www.youtube.com/watch?v=dQw4w9WgXcQ"), nil)
	req.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	rec := httptest.NewRecorder()
	srv.servirMediaFiche(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code %d, corps %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "youtube-nocookie.com/embed/dQw4w9WgXcQ") {
		t.Fatalf("embed youtube attendu, eu : %s", rec.Body.String())
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
