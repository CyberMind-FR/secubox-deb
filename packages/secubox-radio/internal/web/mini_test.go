package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// LE LECTEUR /mini DOIT ÊTRE INCORPORABLE PAR LE RAIL BBS, ET PAR LUI SEUL.
// L'accueil normal reste `frame-ancestors 'none'` (aucun cadrage) ; /mini
// autorise l'origine CadreParent — sinon le widget du rail BBS resterait bloqué
// comme une page PeerTube (#1131m).
func TestMiniEstIncorporableParLeParent(t *testing.T) {
	srv := &Serveur{CadreParent: "https://bbs.gk2.secubox.in"}
	srv.mux = http.NewServeMux()
	srv.mux.HandleFunc("/mini", srv.miniPlayer)

	rec := httptest.NewRecorder()
	srv.miniPlayer(rec, httptest.NewRequest(http.MethodGet, "/mini", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/mini = %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self' https://bbs.gk2.secubox.in") {
		t.Errorf("/mini n'autorise pas le rail BBS à l'incorporer : %s", csp)
	}
	if strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("/mini garde frame-ancestors 'none' : le widget restera bloqué : %s", csp)
	}
}

// L'ACCUEIL NORMAL N'EST PAS INCORPORABLE : la relaxation ne concerne que /mini.
func TestAccueilResteNonIncorporable(t *testing.T) {
	srv := &Serveur{CadreParent: "https://bbs.gk2.secubox.in"}
	if !strings.Contains(srv.politique(), "frame-ancestors 'none'") {
		t.Errorf("l'accueil devrait rester frame-ancestors 'none' : %s", srv.politique())
	}
}

// SANS CadreParent, /mini n'ouvre RIEN : `frame-ancestors 'self'` seul, jamais
// une origine tierce par défaut.
func TestMiniSansParentResteFerme(t *testing.T) {
	srv := &Serveur{}
	csp := srv.politiqueMini()
	if !strings.Contains(csp, "frame-ancestors 'self'") || strings.Contains(csp, "https://") {
		t.Errorf("sans CadreParent, /mini ne doit ouvrir aucune origine : %s", csp)
	}
}
