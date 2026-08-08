package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func jetonHS256(secret, role string, expire time.Duration) string {
	e := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	c := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"sub":"t","role":"%s","iat":%d,"exp":%d}`, role, now, now+int64(expire.Seconds()))))
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(e + "." + c))
	return e + "." + c + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func bancAPI(t *testing.T) *Server {
	t.Helper()
	srv, _ := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	return srv
}

func appelAPI(srv *Server, chemin, jeton string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", chemin, nil)
	if jeton != "" {
		r.Header.Set("Authorization", "Bearer "+jeton)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func TestLAPIRefuseSansJeton(t *testing.T) {
	srv := bancAPI(t)
	if w := appelAPI(srv, "/api/v1/bbs/status", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("API ouverte sans jeton : code %d", w.Code)
	}
}

func TestLAPIRefuseUnJetonSigneAvecUnAutreSecret(t *testing.T) {
	// Un jeton bien FORME n'est pas un jeton VALIDE. C'est la difference entre
	// lire la charge utile et verifier la signature — l'erreur qui laisse
	// entrer quiconque sait fabriquer du base64.
	srv := bancAPI(t)
	faux := jetonHS256("un-autre-secret", "sysop", time.Hour)
	if w := appelAPI(srv, "/api/v1/bbs/status", faux); w.Code != http.StatusUnauthorized {
		t.Errorf("jeton d'un autre secret accepte : code %d", w.Code)
	}
}

func TestLAPIRefuseUnJetonExpire(t *testing.T) {
	srv := bancAPI(t)
	vieux := jetonHS256("le-secret-partage", "sysop", -time.Hour)
	if w := appelAPI(srv, "/api/v1/bbs/status", vieux); w.Code != http.StatusUnauthorized {
		t.Errorf("jeton expire accepte : code %d", w.Code)
	}
}

func TestLAPIRefuseAlgNone(t *testing.T) {
	// « alg: none » est l'attaque classique sur les JWT : le jeton se declare
	// non signe et une implementation naive le croit sur parole.
	srv := bancAPI(t)
	e := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	c := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"role":"sysop","exp":%d}`, time.Now().Add(time.Hour).Unix())))
	if w := appelAPI(srv, "/api/v1/bbs/status", e+"."+c+"."); w.Code != http.StatusUnauthorized {
		t.Errorf("jeton « alg: none » accepte : code %d", w.Code)
	}
}

func TestLAPIAccepteUnJetonValide(t *testing.T) {
	srv := bancAPI(t)
	bon := jetonHS256("le-secret-partage", "sysop", time.Hour)
	w := appelAPI(srv, "/api/v1/bbs/status", bon)
	if w.Code != http.StatusOK {
		t.Fatalf("jeton valide refuse : code %d — %s", w.Code, w.Body.String())
	}
}

func TestSansSecretConfigureLAPIRefuseTout(t *testing.T) {
	// Aucun secret configure ne doit pas vouloir dire « aucune verification ».
	// C'est l'inverse : sans secret, rien ne peut etre authentifie.
	srv, _ := banc(t)
	srv.opt.JWTSecret = ""
	bon := jetonHS256("", "sysop", time.Hour)
	if w := appelAPI(srv, "/api/v1/bbs/status", bon); w.Code == http.StatusOK {
		t.Error("API ouverte alors qu'aucun secret n'est configure")
	}
}

func TestLAPIRefuseUnJetonSansExpiration(t *testing.T) {
	// Un jeton sans « exp » est valable pour toujours : il echappe a toute
	// revocation, et il suffit qu'il fuite UNE fois — dans un journal, une
	// capture reseau, un presse-papiers — pour que l'acces soit perdu
	// definitivement.
	//
	// Ce cas manquait : la mutation qui tolerait un exp absent passait tous les
	// tests, car chacun d'eux fournissait un exp.
	srv := bancAPI(t)
	e := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	c := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"t","role":"sysop"}`))
	m := hmac.New(sha256.New, []byte("le-secret-partage"))
	m.Write([]byte(e + "." + c))
	eternel := e + "." + c + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))

	if w := appelAPI(srv, "/api/v1/bbs/status", eternel); w.Code != http.StatusUnauthorized {
		t.Errorf("jeton sans expiration accepte : code %d", w.Code)
	}
}
