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

// L'ACCUEIL N'EST INCORPORABLE QUE PAR LE HALL SOUVERAIN (#1175) : le bureau
// WebOS embarque le vhost réel de la Radio ; tout autre parent reste bloqué.
func TestAccueilIncorporableParLeHall(t *testing.T) {
	srv := &Serveur{CadreParent: "https://bbs.gk2.secubox.in"}
	csp := srv.politique()
	if !strings.Contains(csp, "frame-ancestors 'self' https://hall.gk2.secubox.in") {
		t.Errorf("l'accueil devrait autoriser le Hall : %s", csp)
	}
	if strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("frame-ancestors 'none' bloquerait le Hall : %s", csp)
	}
}

// SANS CadreParent, /mini n'ouvre à AUCUN tiers arbitraire — mais le Hall
// souverain est toujours autorisé (chaîne hall>bbs>radio, #1175). Pas d'autre
// https:// que hall.gk2.secubox.in / hall.gk2.net.
func TestMiniSansParentAutoriseSeulementHall(t *testing.T) {
	srv := &Serveur{}
	csp := srv.politiqueMini()
	if !strings.Contains(csp, "frame-ancestors 'self' https://hall.gk2.secubox.in https://hall.gk2.net") {
		t.Errorf("sans CadreParent, /mini doit autoriser le Hall (et lui seul) : %s", csp)
	}
	if strings.Contains(csp, "https://bbs") {
		t.Errorf("sans CadreParent, aucun tiers (ex. bbs) ne doit apparaître : %s", csp)
	}
}
