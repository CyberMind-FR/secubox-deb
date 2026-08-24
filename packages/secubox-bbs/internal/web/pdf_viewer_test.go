package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// UN PDF EN LECTEUR INTEGRE NE MARCHE QUE SI LE MEDIA S'ENCADRE. Le corps rend
// `<iframe src="/f/NN">` ; sans autoriser l'encadrement en meme origine, le
// navigateur bloque le cadre (`X-Frame-Options: DENY`, `frame-ancestors 'none'`)
// et la visionneuse reste vide. La reponse /f/ doit donc s'ouvrir a SA propre
// origine — et a elle seule. Les PAGES HTML gardent `DENY` (anti-clickjacking).
func TestLeMediaSEncadreEnMemeOrigine(t *testing.T) {
	srv, s := banc(t)
	uid, err := s.CreateUser("gk2", "Gandalf", store.RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.DeposeFichier(uid, "doc.pdf", "application/pdf", strings.NewReader("%PDF-1.4 test"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarqueFichiersPublics([]int64{f.ID}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/f/"+itoa(f.ID), nil))
	if w.Code != 200 {
		t.Fatalf("le PDF public devrait etre servi : code=%d", w.Code)
	}
	// Encadrable par NOTRE origine, pas par le defaut DENY des pages.
	if xfo := w.Header().Get("X-Frame-Options"); xfo != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options=%q, attendu SAMEORIGIN (sinon le cadre PDF est bloque)", xfo)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("frame-ancestors devrait valoir 'self' pour le media : %s", csp)
	}
	if strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("le media garde frame-ancestors 'none' : le cadre restera bloque : %s", csp)
	}
}

// LES PAGES HTML NE S'ENCADRENT QUE PAR LE HALL SOUVERAIN (#1175). Le bureau
// WebOS embarque le vhost réel du BBS ; tout autre parent reste bloqué. Plus de
// X-Frame-Options DENY (il primerait et bloquerait le Hall) : le cadrage est régi
// par frame-ancestors.
func TestUnePageHtmlAutoriseLeHall(t *testing.T) {
	srv, _ := banc(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if xfo := w.Header().Get("X-Frame-Options"); xfo == "DENY" {
		t.Errorf("X-Frame-Options=DENY bloquerait le Hall ; il ne doit plus être posé")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self' https://hall.gk2.secubox.in") {
		t.Errorf("frame-ancestors doit autoriser le Hall : %s", csp)
	}
	if strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("frame-ancestors 'none' bloquerait le Hall : %s", csp)
	}
}
