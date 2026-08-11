package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func TestUneDonneeHorsFormatEstRefusee(t *testing.T) {
	// La donnee finit dans les arguments d'un programme externe. Elle ne passe
	// pas par un shell — mais se reposer sur UN seul niveau de protection pour
	// une donnee venue du reseau est une habitude qui finit mal.
	for _, mauvais := range []string{
		"; rm -rf /", "$(whoami)", "`id`", "code avec espaces",
		"../../etc/passwd", "trop-court", "", strings.Repeat("a", 200),
		"https://ailleurs.example/piege",
	} {
		if _, err := qrSVG(mauvais); err == nil {
			t.Errorf("donnee acceptee : %q", mauvais)
		}
	}
}

func TestUnCodeDInvitationNormalPasse(t *testing.T) {
	if _, err := exec.LookPath("qrencode"); err != nil {
		t.Skip("qrencode absent de cette machine")
	}
	svg, err := qrSVG("aZ3_kd92LmQpX1yTnB7Uc0")
	if err != nil {
		t.Fatalf("code legitime refuse : %v", err)
	}
	if !strings.Contains(string(svg), "<svg") {
		t.Errorf("la sortie n'est pas un SVG : %.60s", svg)
	}
}

func TestLeQrDInvitationPorteUneADRESSEPasLeCodeNu(t *testing.T) {
	// UN QR QUI NE CONTIENT QU'UN CODE EST INUTILISABLE. Le telephone affiche
	// une chaine inerte : rien a toucher, rien a ouvrir. Il faut alors la
	// recopier a la main dans la barre d'adresse en devinant le chemin — ce
	// que personne ne fera.
	//
	// Ce test existe parce que le premier jet encodait le code seul, alors que
	// le commentaire au-dessus affirmait construire l'adresse complete. Le
	// commentaire decrivait une intention ; le code faisait autre chose.
	srv, _ := banc(t)
	var recu string
	srv.encodeQR = func(donnee string) ([]byte, error) {
		recu = donnee
		return []byte("<svg/>"), nil
	}
	uid, _ := srv.Store().CreateUser("gk2", "G", store.RoleSysop)
	srv.Store().SetRoleSysopPourTest(uid)
	jeton, _ := srv.Store().NewSession(uid, "", "")

	r := httptest.NewRequest("GET", "/sysop/qr?code=aZ3_kd92LmQpX1yTnB7Uc0", nil)
	r.Host = "bbs.gk2.secubox.in"
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	attendu := "https://bbs.gk2.secubox.in/invite/aZ3_kd92LmQpX1yTnB7Uc0"
	if recu != attendu {
		t.Errorf("le QR encode %q\n  au lieu de %q", recu, attendu)
	}
}

func TestUnCodeHorsFormatNeProduitAucunQr(t *testing.T) {
	srv, _ := banc(t)
	var appele bool
	srv.encodeQR = func(string) ([]byte, error) { appele = true; return nil, nil }
	uid, _ := srv.Store().CreateUser("gk2", "G", store.RoleSysop)
	srv.Store().SetRoleSysopPourTest(uid)
	jeton, _ := srv.Store().NewSession(uid, "", "")
	for _, mauvais := range []string{"../../etc/passwd", "a b", "", "'; rm -rf /"} {
		r := httptest.NewRequest("GET", "/sysop/qr?code="+url.QueryEscape(mauvais), nil)
		r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code == http.StatusOK {
			t.Errorf("code accepte : %q", mauvais)
		}
	}
	if appele {
		t.Error("l'encodeur a ete appele avec une donnee refusee")
	}
}
