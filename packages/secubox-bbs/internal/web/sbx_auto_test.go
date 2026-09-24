package web

import (
	"net/http"
	"os"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func auto(t *testing.T, srv *Server, vers string, avecHall bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "/sbx/auto?vers="+vers, nil)
	if avecHall {
		r.AddCookie(&http.Cookie{Name: "secubox_session", Value: "jeton-du-hall"})
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func cookieNomme(w *httptest.ResponseRecorder, nom string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == nom {
			return c
		}
	}
	return nil
}

func TestLEntreeAutomatiqueOuvreLaSessionEtRevient(t *testing.T) {
	// #1373 : embarquée dans le Hall, la BBS n'offrait aucune entrée.
	srv, s := banc(t)
	srv.verif = verifFixe("sbx-ff90aec2d8d8", "user")
	w := auto(t, srv, "/t/1109", true)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/t/1109" {
		t.Fatalf("code %d vers %q", w.Code, w.Header().Get("Location"))
	}
	if c := cookieNomme(w, cookieSession); c == nil || c.Value == "" {
		t.Fatal("aucune session BBS posée")
	}
	id, err := s.UserByHandle("sbx-ff90aec2d8d8")
	if err != nil {
		t.Fatal("le compte d'appareil n'a pas été créé")
	}
	if u, _ := s.UserInfo(id); u.Role != store.RoleMember {
		t.Errorf("rôle %q, attendu membre (jamais sysop d'office)", u.Role)
	}
}

func TestSansSessionHallOnRevientSansBoucle(t *testing.T) {
	srv, _ := banc(t)
	srv.verif = verifRefuse
	for _, avec := range []bool{false, true} {
		w := auto(t, srv, "/c/general", avec)
		if w.Header().Get("Location") != "/c/general" {
			t.Errorf("hall=%v : renvoyé vers %q, attendu la page demandée", avec, w.Header().Get("Location"))
		}
		if cookieNomme(w, cookieSession) != nil {
			t.Errorf("hall=%v : une session a été ouverte sans preuve", avec)
		}
		if c := cookieNomme(w, cookieAutoNon); c == nil || c.HttpOnly {
			t.Errorf("hall=%v : drapeau anti-boucle absent ou illisible par le script", avec)
		}
	}
}

func TestLEntreeAutomatiqueNEstPasUnTremplin(t *testing.T) {
	srv, _ := banc(t)
	srv.verif = verifFixe("gk2", "admin")
	for _, v := range []string{"https://ailleurs.example", "//ailleurs.example", "/\\ailleurs.example"} {
		if loc := auto(t, srv, v, true).Header().Get("Location"); loc != "/" {
			t.Errorf("vers=%q redirige vers %q", v, loc)
		}
	}
}

func TestLaPageDitSiLOnEstConnecteEtOffreLEntreeEmbarquee(t *testing.T) {
	srv, _ := banc(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	p := w.Body.String()
	if !strings.Contains(p, `data-connecte="0"`) {
		t.Error("la page anonyme ne porte pas data-connecte=\"0\"")
	}
	if !strings.Contains(p, `class="embed-entree"`) || !strings.Contains(p, `href="/sbx/entrer"`) {
		t.Error("la bande d'entrée embarquée manque à la page anonyme")
	}
}

func TestLaDeconnexionNEstPasDefaiteParLeHall(t *testing.T) {
	srv, s := banc(t)
	s.SyncExternalUsers([]store.ExternalUser{{Handle: "gk2", Display: "Gk2", Role: store.RoleSysop}})
	srv.verif = verifFixe("gk2", "admin")
	r := httptest.NewRequest("GET", "/compte", nil)
	r.AddCookie(&http.Cookie{Name: "secubox_session", Value: "jeton-du-hall"})
	r.AddCookie(&http.Cookie{Name: cookieAutoNon, Value: "1"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "gk2 · sysop") {
		t.Error("après déconnexion, la session du Hall rouvre la BBS")
	}
}

func poseRegistreAppareils(t *testing.T, contenu string) {
	t.Helper()
	p := t.TempDir() + "/appareils.json"
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	ancien := cheminAppareils
	cheminAppareils = p
	t.Cleanup(func() { cheminAppareils = ancien })
}

func TestUnAppareilEntreSousSonNomDeclare(t *testing.T) {
	poseRegistreAppareils(t, `{"appareils":[{"compte":"sbx-501cad3a1be8","nom":"  Gandalf  "}]}`)
	srv, s := banc(t)
	srv.verif = verifFixe("sbx-501cad3a1be8", "user")
	auto(t, srv, "/", true)
	id, _ := s.UserByHandle("sbx-501cad3a1be8")
	if u, _ := s.UserInfo(id); u.Display != "Gandalf" || u.Role != store.RoleMember {
		t.Errorf("compte créé : nom %q rôle %q, attendu Gandalf / membre", u.Display, u.Role)
	}
}

func TestLeNomDeclareRattrapeUnCompteDejaCreeMaisPasUnNomChoisi(t *testing.T) {
	poseRegistreAppareils(t, `{"appareils":[{"compte":"sbx-ff90aec2d8d8","nom":"Gk2"}]}`)
	srv, s := banc(t)
	srv.verif = verifFixe("sbx-ff90aec2d8d8", "user")
	id, _ := s.CreateUser("sbx-ff90aec2d8d8", "sbx-ff90aec2d8d8", store.RoleMember)
	auto(t, srv, "/", true)
	if u, _ := s.UserInfo(id); u.Display != "Gk2" {
		t.Errorf("nom technique non remplacé : %q", u.Display)
	}
	s.PoseNomAffiche(id, "Mon choix")
	auto(t, srv, "/", true)
	if u, _ := s.UserInfo(id); u.Display != "Mon choix" {
		t.Errorf("le nom choisi par le membre a été écrasé : %q", u.Display)
	}
}

func TestUnGuestDuHallNEstQueLecteur(t *testing.T) {
	poseRegistreAppareils(t, `{"appareils":[]}`)
	srv, s := banc(t)
	srv.verif = verifFixe("sbx-7d263ff2a247", "guest")
	auto(t, srv, "/", true)
	id, _ := s.UserByHandle("sbx-7d263ff2a247")
	if u, _ := s.UserInfo(id); u.Role != store.RoleGuest {
		t.Errorf("rôle %q, attendu guest (lecteur)", u.Role)
	}
}

func TestNomAffichableBorne(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{{"Gandalf", true}, {"  a  b ", true}, {"", false}, {"x\u0007y", false},
		{strings.Repeat("é", 41), false}} {
		if _, ok := nomAffichable(c.in); ok != c.ok {
			t.Errorf("%q : ok=%v", c.in, ok)
		}
	}
}
