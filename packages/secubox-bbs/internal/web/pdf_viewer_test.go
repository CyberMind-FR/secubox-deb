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

// LES PAGES HTML NE S'ENCADRENT PAS. La relaxation ne concerne que /f/ ; une
// page de contenu garde la protection anti-clickjacking stricte.
func TestUnePageHtmlGardeXFrameDeny(t *testing.T) {
	srv, _ := banc(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if xfo := w.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("X-Frame-Options d'une page HTML=%q, attendu DENY", xfo)
	}
}
