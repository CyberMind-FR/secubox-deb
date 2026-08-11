package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// appelSysop joue une requete authentifiee par JWT, comme le panneau d'admin.
// Distinct de `appelAPI`, qui ne fait que des GET sans corps.
func appelSysop(t *testing.T, srv *Server, methode, chemin, corps string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var r *http.Request
	if corps == "" {
		r = httptest.NewRequest(methode, chemin, nil)
	} else {
		r = httptest.NewRequest(methode, chemin, strings.NewReader(corps))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+jetonHS256("le-secret-partage", "admin", time.Hour))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	var j map[string]any
	json.Unmarshal(w.Body.Bytes(), &j)
	return w, j
}

func TestLApiSysopExigeUnJeton(t *testing.T) {
	// Ces routes listent les comptes et reinitialisent des mots de passe. Sans
	// jeton, elles offriraient l'annuaire du BBS et la prise de controle de
	// n'importe quel compte a qui atteint la socket.
	srv, _ := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	for _, chemin := range []string{
		"/api/v1/bbs/users", "/api/v1/bbs/invites", "/api/v1/bbs/settings",
	} {
		r := httptest.NewRequest("GET", chemin, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s sans jeton : code %d, attendu 401", chemin, w.Code)
		}
	}
}

func TestLApiListeLesComptesAvecLeurSource(t *testing.T) {
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	peuple(t, s)
	s.CreateUser("amie", "Amie", store.RoleMember)

	w, j := appelSysop(t, srv, "GET", "/api/v1/bbs/users", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code %d : %s", w.Code, w.Body.String())
	}
	users, _ := j["users"].([]any)
	if len(users) != 2 {
		t.Fatalf("%d comptes, attendu 2", len(users))
	}
	// La SOURCE doit figurer : sans elle, le panneau proposerait de
	// reinitialiser le mot de passe d'un compte delegue, geste qui echouerait
	// silencieusement du point de vue de l'utilisateur.
	for _, u := range users {
		m := u.(map[string]any)
		if m["source"] == "" || m["source"] == nil {
			t.Errorf("compte %v sans source d'authentification", m["handle"])
		}
	}
}

func TestLApiReinitialiseEtCoupeLesSessions(t *testing.T) {
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	peuple(t, s)
	amie, _ := s.CreateUser("amie", "Amie", store.RoleMember)
	jeton, _ := s.NewSession(amie, "", "")

	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/password",
		`{"id":`+itoa(amie)+`,"password":"une-phrase-assez-longue"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code %d : %s", w.Code, w.Body.String())
	}
	if !srv.auth.Verify(amie, "une-phrase-assez-longue") {
		t.Error("le mot de passe n'a pas ete pose")
	}
	if _, err := s.UserBySession(jeton); err == nil {
		t.Error("la session ouverte avant la reinitialisation survit")
	}
}

func TestLApiRefuseUnMotDePasseTropCourt(t *testing.T) {
	// La politique doit valoir pour LES DEUX portes. Une API qui ne la porterait
	// pas rendrait la regle de la console decorative.
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	peuple(t, s)
	amie, _ := s.CreateUser("amie", "Amie", store.RoleMember)

	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/password",
		`{"id":`+itoa(amie)+`,"password":"court"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code %d, attendu 400", w.Code)
	}
	if srv.auth.Verify(amie, "court") {
		t.Error("le mot de passe court a ete pose malgre le refus")
	}
}

func TestLApiRefuseDeReinitialiserUnCompteDelegue(t *testing.T) {
	// Poser un mot de passe local sur un compte verifie par secubox-auth
	// annoncerait un succes sans effet : la connexion continuerait d'echouer,
	// et l'on chercherait la cause partout sauf ici.
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	peuple(t, s)
	if _, err := s.SyncExternalUsers([]store.ExternalUser{
		{Handle: "operator", Display: "Operator", Role: store.RoleMember},
	}); err != nil {
		t.Fatalf("synchronisation impossible : %v", err)
	}
	id, err := s.UserByHandle("operator")
	if err != nil {
		t.Fatalf("compte delegue absent : %v", err)
	}
	w, j := appelSysop(t, srv, "POST", "/api/v1/bbs/users/password",
		`{"id":`+itoa(id)+`,"password":"une-phrase-assez-longue"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("code %d, attendu 409 : %s", w.Code, w.Body.String())
	}
	if !strings.Contains(j["error"].(string), "secubox-auth") {
		t.Errorf("message peu clair : %v", j["error"])
	}
	if srv.auth.Verify(id, "une-phrase-assez-longue") {
		t.Error("un mot de passe local a ete pose sur un compte delegue")
	}
}

func TestLApiDesactiveEtReactive(t *testing.T) {
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	peuple(t, s)
	amie, _ := s.CreateUser("amie", "Amie", store.RoleMember)

	if w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/disable",
		`{"id":`+itoa(amie)+`}`); w.Code != http.StatusOK {
		t.Fatalf("desactivation : code %d", w.Code)
	}
	if _, err := s.UserByHandle("amie"); err == nil {
		t.Error("le compte desactive est encore resolu")
	}
	if w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/enable",
		`{"id":`+itoa(amie)+`}`); w.Code != http.StatusOK {
		t.Fatalf("reactivation : code %d", w.Code)
	}
	if _, err := s.UserByHandle("amie"); err != nil {
		t.Error("le compte reactive n'est pas resolu")
	}
}

func TestLApiDesReglagesRefuseUnLienNonHttp(t *testing.T) {
	// Seconde porte d'ecriture des reglages : si elle ne validait pas, la
	// validation de la console deviendrait decorative — le lien finit dans un
	// href servi a tous les membres, d'ou qu'il vienne.
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	peuple(t, s)

	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/settings",
		`{"instance":"javascript:alert(1)","invitation":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code %d, attendu 400", w.Code)
	}
	if v, _ := s.Reglage(store.CleMastodonInstance); v != "" {
		t.Errorf("un lien javascript: a ete stocke : %q", v)
	}

	w, j := appelSysop(t, srv, "POST", "/api/v1/bbs/settings",
		`{"instance":"https://social.exemple.fr","invitation":"https://social.exemple.fr/invite/x"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("reglage legitime refuse : %s", w.Body.String())
	}
	if j["instance"] != "https://social.exemple.fr" {
		t.Errorf("relecture = %v", j["instance"])
	}
}
