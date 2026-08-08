package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func banc(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	root := t.TempDir()
	s, err := store.Open(filepath.Join(root, "bbs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	srv, err := New(s, Options{Titre: "Banc", Secrets: filepath.Join(root, "secrets")})
	if err != nil {
		t.Fatal(err)
	}
	return srv, s
}

func peuple(t *testing.T, s *store.Store) (int64, int64) {
	t.Helper()
	uid, err := s.CreateUser("gk2", "Gandalf", store.RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := s.CreateCategory("atelier", "Atelier", "")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := s.NewThread(cat, uid, "Fil visible de dehors", "corps public", store.VisPublic)
	s.NewThread(cat, uid, "Coordonnees privees", "corps prive", store.VisLocal)
	return uid, pub
}

func TestUnVisiteurNeVoitAucunFilLocal(t *testing.T) {
	// La page d'accueil est servie a internet. Un fil local qui y apparaitrait
	// aurait deja divulgue son titre.
	srv, s := banc(t)
	peuple(t, s)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	body := w.Body.String()

	if !strings.Contains(body, "Fil visible de dehors") {
		t.Error("le fil public n'apparait pas pour un visiteur")
	}
	if strings.Contains(body, "Coordonnees privees") {
		t.Error("un titre de fil LOCAL est servi a un visiteur non connecte")
	}
}

func TestUnVisiteurNePeutPasOuvrirUnFilLocal(t *testing.T) {
	// Masquer un fil dans la liste ne suffit pas : l'adresse reste devinable.
	// C'est la meme faille que « la page d'administration n'est pas dans le
	// menu » — elle repond quand meme a qui tape l'adresse.
	srv, s := banc(t)
	peuple(t, s)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/t/2", nil))

	// Le premier jet n'assertait que l'absence du CORPS. Insuffisant : sans la
	// garde, la page se construit quand meme, les messages sont filtres a zero
	// par PublicPostsOf, mais LE TITRE reste affiche en tete — et un titre
	// comme « Coordonnees privees » a deja tout dit. La mutation qui retirait
	// le 404 passait donc inapercue.
	if w.Code != http.StatusNotFound {
		t.Errorf("un fil local repond %d au lieu de 404", w.Code)
	}
	for _, fuite := range []string{"corps prive", "Coordonnees privees"} {
		if strings.Contains(w.Body.String(), fuite) {
			t.Errorf("acces direct a un fil local : %q est servi", fuite)
		}
	}
}

func TestPublierSansJetonAntiRejeuEstRefuse(t *testing.T) {
	// Sans ce jeton, un site tiers peut faire poster un membre connecte a son
	// insu : le navigateur joint le cookie de session tout seul.
	srv, s := banc(t)
	uid, th := peuple(t, s)
	jeton, _ := s.NewSession(uid, "", "")

	f := url.Values{"body": {"message force"}, "visibility": {"local"}}
	r := httptest.NewRequest("POST", "/t/"+itoa(th)+"/reply", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code == http.StatusOK || w.Code == http.StatusSeeOther {
		t.Errorf("message accepte sans jeton anti-rejeu (code %d)", w.Code)
	}
	posts, _ := s.PostsOf(th)
	if len(posts) != 1 {
		t.Errorf("%d messages : la requete forgee a ecrit", len(posts))
	}
}

func TestLeCookieDeSessionEstProtege(t *testing.T) {
	// HttpOnly : un script ne doit pas pouvoir lire le jeton. SameSite : le
	// navigateur ne doit pas le joindre a une requete venue d'un autre site.
	srv, s := banc(t)
	uid, err := s.CreateUser("gk2", "Gandalf", store.RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Auth().SetPassword(uid, "mot-de-passe-assez-long"); err != nil {
		t.Fatal(err)
	}

	c := connexion(t, srv, "gk2", "mot-de-passe-assez-long")
	if c == nil {
		t.Fatal("pas de cookie de session apres une connexion valide")
	}
	if !c.HttpOnly {
		t.Error("cookie de session lisible par un script")
	}
	if c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode {
		t.Error("cookie de session sans SameSite")
	}
	if c.Path != "/" {
		t.Errorf("chemin du cookie inattendu : %q", c.Path)
	}
}

func TestUnMotDePasseFauxNeCreeAucuneSession(t *testing.T) {
	srv, s := banc(t)
	uid, _ := s.CreateUser("gk2", "Gandalf", store.RoleSysop)
	srv.Auth().SetPassword(uid, "le-bon-mot-de-passe")

	if c := connexion(t, srv, "gk2", "pas-le-bon"); c != nil && c.Value != "" {
		t.Error("une session est ouverte malgre un mot de passe faux")
	}
}

func TestUnCompteSansMotDePasseNeSeConnectePas(t *testing.T) {
	// Un compte recree par la reconstruction de l'index n'a pas d'entree dans
	// le fichier de hashes. Il ne doit pas pour autant devenir un compte sans
	// mot de passe : c'est exactement le contraire qui doit se produire.
	srv, s := banc(t)
	s.CreateUser("fantome", "Fantome", store.RoleMember)
	if c := connexion(t, srv, "fantome", ""); c != nil && c.Value != "" {
		t.Error("connexion acceptee sur un compte sans mot de passe")
	}
	if c := connexion(t, srv, "fantome", "n importe quoi"); c != nil && c.Value != "" {
		t.Error("connexion acceptee sur un compte sans mot de passe")
	}
}

func connexion(t *testing.T, srv *Server, handle, pw string) *http.Cookie {
	t.Helper()
	f := url.Values{"handle": {handle}, "password": {pw}}
	r := httptest.NewRequest("POST", "/login", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	for _, k := range w.Result().Cookies() {
		if k.Name == cookieSession {
			return k
		}
	}
	return nil
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
