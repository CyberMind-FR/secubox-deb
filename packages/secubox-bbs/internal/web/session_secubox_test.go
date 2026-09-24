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

// verifFixe : un secubox-auth qui reconnait toujours la meme identite.
func verifFixe(user, groupes string) verifSession {
	return func(string) (sessionSecubox, bool) {
		return sessionSecubox{User: user, Groupes: groupes}, true
	}
}

func verifRefuse(string) (sessionSecubox, bool) { return sessionSecubox{}, false }

func pageAvecSessionSecubox(t *testing.T, srv *Server) string {
	t.Helper()
	r := httptest.NewRequest("GET", "/compte", nil)
	r.AddCookie(&http.Cookie{Name: "secubox_session", Value: "jeton-du-hall"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w.Body.String()
}

func TestLaSessionDuHallOuvreUnCompteSecubox(t *testing.T) {
	// #1369 : un iPhone connecte au Hall arrivait ici anonyme, sans un bouton.
	srv, s := banc(t)
	s.SyncExternalUsers([]store.ExternalUser{{Handle: "gk2", Display: "Gk2", Role: store.RoleSysop}})
	srv.verif = verifFixe("gk2", "admin")
	if p := pageAvecSessionSecubox(t, srv); !strings.Contains(p, "gk2 · sysop") {
		t.Errorf("la session du Hall n'ouvre pas le compte gk2 :\n%.400s", p)
	}
}

func TestLaSessionDuHallNOuvreJamaisUnHomonymeLocal(t *testing.T) {
	// Un compte local du meme nom peut etre quelqu'un d'autre : sans adoption
	// explicite, le nom SecuBox ne l'ouvre pas.
	srv, s := banc(t)
	s.CreateUser("gk2", "Autre", store.RoleSysop)
	srv.verif = verifFixe("gk2", "admin")
	if p := pageAvecSessionSecubox(t, srv); strings.Contains(p, "gk2 · sysop") {
		t.Error("un compte local homonyme a ete ouvert par la session du Hall")
	}
	if err := s.AdopteCompte("gk2"); err != nil {
		t.Fatal(err)
	}
	if p := pageAvecSessionSecubox(t, srv); !strings.Contains(p, "gk2 · sysop") {
		t.Error("apres adoption, la session du Hall n'ouvre toujours pas gk2")
	}
}

func TestUneSessionRefuseeParSecuboxResteAnonyme(t *testing.T) {
	srv, s := banc(t)
	s.SyncExternalUsers([]store.ExternalUser{{Handle: "gk2", Display: "Gk2", Role: store.RoleSysop}})
	srv.verif = verifRefuse
	if p := pageAvecSessionSecubox(t, srv); strings.Contains(p, "gk2 · sysop") {
		t.Error("une session refusee par secubox-auth ouvre quand meme le compte")
	}
}

func appelAdmin(t *testing.T, srv *Server, methode, chemin, corps string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var r *http.Request
	if corps == "" {
		r = httptest.NewRequest(methode, chemin, nil)
	} else {
		r = httptest.NewRequest(methode, chemin, strings.NewReader(corps))
	}
	r.Header.Set("Authorization", "Bearer "+jetonHS256("le-secret-partage", "x", time.Hour))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	var j map[string]any
	json.Unmarshal(w.Body.Bytes(), &j)
	return w, j
}

func TestLesRoutesDAdministrationExigentUnAdministrateur(t *testing.T) {
	// La signature seule laissait passer le jeton d'un appareil invite.
	srv, _ := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	chemins := []string{"/api/v1/bbs/users", "/api/v1/bbs/invites", "/api/v1/bbs/settings",
		"/api/v1/bbs/comptes/etat?h=gk2"}

	srv.verif = verifFixe("sbx-4e943496630e", "guest")
	for _, c := range chemins {
		if w, _ := appelAdmin(t, srv, "GET", c, ""); w.Code != http.StatusForbidden {
			t.Errorf("%s avec un jeton d'invite : code %d, attendu 403", c, w.Code)
		}
	}
	srv.verif = verifRefuse
	for _, c := range chemins {
		if w, _ := appelAdmin(t, srv, "GET", c, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s avec une session revoquee : code %d, attendu 401", c, w.Code)
		}
	}
	srv.verif = nil
	if w, _ := appelAdmin(t, srv, "GET", chemins[0], ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("sans secubox-auth : code %d, attendu 503 (ferme)", w.Code)
	}
}

func TestEtatEtSynchronisationDesComptes(t *testing.T) {
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	srv.verif = verifFixe("gk2", "admin")
	s.CreateUser("gk2", "Gk2", store.RoleSysop) // local, comme sur gk2

	_, j := appelAdmin(t, srv, "GET", "/api/v1/bbs/comptes/etat?h=gk2&h=inconnu", "")
	cs := j["comptes"].(map[string]any)
	if g := cs["gk2"].(map[string]any); g["source"] != "local" || g["existe"] != true {
		t.Errorf("etat de gk2 : %v", g)
	}
	if i := cs["inconnu"].(map[string]any); i["existe"] != false {
		t.Errorf("un inconnu se dit existant : %v", i)
	}

	// Liste vide : refusee, elle desactiverait tous les comptes synchronises.
	if w, _ := appelAdmin(t, srv, "POST", "/api/v1/bbs/comptes/sync", `{"comptes":[]}`); w.Code != 400 {
		t.Errorf("liste vide acceptee : code %d", w.Code)
	}
	// Adopter un nom absent de SecuBox : refuse.
	if w, _ := appelAdmin(t, srv, "POST", "/api/v1/bbs/comptes/sync",
		`{"comptes":[{"handle":"admin","role":"admin"}],"adopter":["gk2"]}`); w.Code != 400 {
		t.Errorf("adoption d'un nom inconnu de SecuBox acceptee : code %d", w.Code)
	}
	w, j := appelAdmin(t, srv, "POST", "/api/v1/bbs/comptes/sync",
		`{"comptes":[{"handle":"gk2","nom":"Gk2","role":"admin"},{"handle":"operator","role":"operator"}],"adopter":["gk2"]}`)
	if w.Code != 200 {
		t.Fatalf("sync : %d %v", w.Code, j)
	}
	_, j = appelAdmin(t, srv, "GET", "/api/v1/bbs/comptes/etat?h=gk2&h=operator", "")
	cs = j["comptes"].(map[string]any)
	if g := cs["gk2"].(map[string]any); g["source"] != "secubox" || g["role"] != "sysop" {
		t.Errorf("gk2 apres adoption : %v", g)
	}
	if o := cs["operator"].(map[string]any); o["source"] != "secubox" || o["role"] != "member" {
		t.Errorf("operator apres sync : %v", o)
	}
}
