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

func TestLApiRefuseUnMotDePasseVide(t *testing.T) {
	// La longueur minimale a ete retiree ; le refus du VIDE doit valoir pour LES
	// DEUX portes. Une API qui l'accepterait poserait un compte ou la chaine
	// vide authentifie.
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	peuple(t, s)
	amie, _ := s.CreateUser("amie", "Amie", store.RoleMember)

	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/password",
		`{"id":`+itoa(amie)+`,"password":""}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code %d, attendu 400", w.Code)
	}
	if srv.auth.Verify(amie, "") {
		t.Error("un mot de passe vide a ete pose")
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

func TestLApiSupprimeUnCompteSansEffacerSonContenu(t *testing.T) {
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	sysop, _ := peuple(t, s)
	partant, _ := s.CreateUser("partant", "Partant", store.RoleMember)
	cat, _ := s.CreateCategory("coin", "Coin", "")
	fil, _ := s.NewThread(cat, partant, "Fil du partant", "un corps", store.VisLocal)
	s.Reply(fil, sysop, "ma reponse, qui doit survivre", store.VisLocal)
	srv.auth.SetPassword(partant, "un-mot-de-passe")

	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/delete",
		`{"id":`+itoa(partant)+`}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code %d : %s", w.Code, w.Body.String())
	}
	if _, err := s.UserByHandle("partant"); err == nil {
		t.Error("le compte est encore resolu")
	}
	// L'empreinte disparait aussi : sinon un secret survit a son compte.
	if srv.auth.Verify(partant, "un-mot-de-passe") {
		t.Error("l'empreinte a survecu au compte")
	}
	if posts, _ := s.PostsOf(fil); len(posts) != 2 {
		t.Errorf("%d messages apres suppression, attendu 2", len(posts))
	}
}

func TestLApiRepondUnCompteDelegueEnLocal(t *testing.T) {
	// C'est la sortie du cul-de-sac : un compte delegue n'avait aucun bouton,
	// et l'exploitant ne pouvait ni le depanner ni lui rendre un mot de passe.
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	peuple(t, s)
	s.SyncExternalUsers([]store.ExternalUser{
		{Handle: "delegue", Display: "Delegue", Role: store.RoleMember}})
	id, err := s.UserByHandle("delegue")
	if err != nil {
		t.Fatal(err)
	}

	// Sans mot de passe, la reprise est refusee : le compte deviendrait local
	// SANS empreinte, donc incapable de se connecter.
	if w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/local",
		`{"id":`+itoa(id)+`}`); w.Code != http.StatusBadRequest {
		t.Errorf("reprise sans mot de passe : code %d, attendu 400", w.Code)
	}

	w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/local",
		`{"id":`+itoa(id)+`,"password":"le-mot-de-passe-local"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code %d : %s", w.Code, w.Body.String())
	}
	if src, _ := s.AuthSourceParID(id); src != "local" {
		t.Errorf("source = %q, attendu local", src)
	}
	if !srv.auth.Verify(id, "le-mot-de-passe-local") {
		t.Error("le mot de passe local ne fonctionne pas")
	}
	// Et il est desormais reinitialisable comme n'importe quel compte.
	if w, _ := appelSysop(t, srv, "POST", "/api/v1/bbs/users/password",
		`{"id":`+itoa(id)+`,"password":"un-autre-mot-de-passe"}`); w.Code != http.StatusOK {
		t.Errorf("reinitialisation apres reprise : code %d", w.Code)
	}
}
