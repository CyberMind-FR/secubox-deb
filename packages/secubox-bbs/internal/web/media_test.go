package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func bancMedia(t *testing.T) (*Server, string) {
	t.Helper()
	srv, _ := banc(t)
	parc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(parc, "1"), 0o750); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(parc, "1", "ep.m4a"), []byte("AUDIO"), 0o640)
	// Un fichier HORS du parc, qu'aucune reference ne doit pouvoir atteindre.
	os.WriteFile(filepath.Join(filepath.Dir(parc), "secret.txt"), []byte("SECRET"), 0o600)
	// Deux parcs declares, comme sur la board : l'eMMC et le SSD.
	srv.opt.PodcastRacine = parc + ",/n/existe/pas"
	srv.resoudreEpisode = func(id int64) (string, string, bool) {
		switch id {
		case 1:
			return filepath.Join(parc, "1", "ep.m4a"), "audio/mp4", true
		case 2: // une base compromise ou incoherente pointe ailleurs
			return filepath.Join(filepath.Dir(parc), "secret.txt"), "text/plain", true
		case 3:
			return filepath.Join(parc, "1", "..", "..", "secret.txt"), "audio/mp4", true
		}
		return "", "", false
	}
	return srv, parc
}

func TestUnEpisodeConnuEstServi(t *testing.T) {
	srv, _ := bancMedia(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/media/ep/1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	if w.Body.String() != "AUDIO" {
		t.Errorf("contenu servi : %q", w.Body.String())
	}
	if w.Header().Get("Accept-Ranges") != "bytes" {
		t.Error("pas de lecture par plages : impossible de se deplacer dans un episode d'une heure")
	}
}

func TestUnCheminHorsDuParcEstRefuse(t *testing.T) {
	// LA GARDE DE CETTE ROUTE. Le chemin ne vient pas de l'appelant mais d'une
	// base tierce — celle du podcaster. Lui faire confiance sans verifier
	// reviendrait a servir n'importe quel fichier lisible par le service des
	// qu'une ligne de cette base serait fausse ou modifiee.
	srv, _ := bancMedia(t)
	for _, id := range []string{"2", "3"} {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/media/ep/"+id, nil))
		if w.Code == http.StatusOK {
			t.Errorf("episode %s : fichier hors du parc servi (%q)", id, w.Body.String())
		}
	}
}

func TestPlusieursParcsSontAcceptes(t *testing.T) {
	// Le podcaster range ses medias a deux endroits : l'eMMC pour les anciens
	// episodes, le SSD pour les imports recents. N'en declarer qu'un refusait
	// tout le second parc — et le refus etait CORRECT, c'est la configuration
	// qui etait incomplete.
	srv, parc := bancMedia(t)
	second := t.TempDir()
	os.WriteFile(filepath.Join(second, "autre.mp3"), []byte("SECOND"), 0o640)
	srv.opt.PodcastRacine = parc + ", " + second
	srv.resoudreEpisode = func(id int64) (string, string, bool) {
		if id == 7 {
			return filepath.Join(second, "autre.mp3"), "audio/mpeg", true
		}
		return "", "", false
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/media/ep/7", nil))
	if w.Code != http.StatusOK || w.Body.String() != "SECOND" {
		t.Errorf("second parc refuse : code %d, corps %q", w.Code, w.Body.String())
	}
}

func TestUnEpisodeInconnuRepondQuatreCentQuatre(t *testing.T) {
	srv, _ := bancMedia(t)
	for _, chemin := range []string{"/media/ep/999", "/media/ep/abc", "/media/ep/", "/media/ep/-1"} {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", chemin, nil))
		if w.Code == http.StatusOK {
			t.Errorf("%s a repondu 200", chemin)
		}
	}
}

func TestLaPolitiqueAutoriseLaVideoEtLAudioQuandIlsSontConfigures(t *testing.T) {
	srv, _ := banc(t)
	srv.opt.PeerTubeOrigine = "https://peertube.gk2.secubox.in"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	p := w.Header().Get("Content-Security-Policy")
	if !contientTxt(p, "frame-src https://peertube.gk2.secubox.in") {
		t.Errorf("le lecteur video restera vide : %s", p)
	}
	if !contientTxt(p, "media-src 'self'") {
		t.Errorf("l'audio servi par nous sera bloque : %s", p)
	}
	// L'ouverture reste MINIMALE : pas de scripts venus de PeerTube.
	if contientTxt(p, "script-src 'self' https://peertube") {
		t.Errorf("script-src elargi sans raison : %s", p)
	}
}

func TestSansPeerTubeConfigureAucuneOrigineNEstOuverte(t *testing.T) {
	srv, _ := banc(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	p := w.Header().Get("Content-Security-Policy")
	if contientTxt(p, "https://") {
		t.Errorf("origine externe autorisee sans configuration : %s", p)
	}
	if !contientTxt(p, "frame-src 'none'") {
		t.Errorf("frame-src devrait etre ferme : %s", p)
	}
}

func contientTxt(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
