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

func jetonPour(sub string) string {
	return jetonHS256Sub("le-secret-partage", sub, "member", time.Hour)
}

func bancMembre(t *testing.T) (*Server, *store.Store, int64) {
	t.Helper()
	srv, s := banc(t)
	srv.opt.JWTSecret = "le-secret-partage"
	uid, _ := s.CreateUser("cedre83", "Cedre", store.RoleMember)
	cat, _ := s.CreateCategory("atelier", "Atelier", "")
	s.NewThread(cat, uid, "Fil public", "corps public", store.VisPublic)
	s.NewThread(cat, uid, "Fil local", "corps local", store.VisLocal)
	return srv, s, uid
}

func api(srv *Server, methode, chemin, jeton, corps string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(methode, chemin, strings.NewReader(corps))
	if jeton != "" {
		r.Header.Set("Authorization", "Bearer "+jeton)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func TestUnJetonSansSujetConnuNOuvreRien(t *testing.T) {
	// La signature prouve que le jeton vient du noyau, pas QUI le presente.
	// Sans resolution du sujet vers un compte du BBS, n'importe quel jeton
	// valide de la board — celui d'un autre module, d'un service — agirait au
	// nom de personne, donc au nom de tout le monde.
	srv, _, _ := bancMembre(t)
	w := api(srv, "GET", "/api/v1/bbs/m/salons", jetonPour("inconnu-ici"), "")
	if w.Code == http.StatusOK {
		t.Errorf("jeton d'un sujet inconnu accepte : %d", w.Code)
	}
}

func TestUnMembreVoitSesSalonsEtSesFils(t *testing.T) {
	srv, _, _ := bancMembre(t)
	w := api(srv, "GET", "/api/v1/bbs/m/salons", jetonPour("cedre83"), "")
	if w.Code != http.StatusOK {
		t.Fatalf("code %d : %s", w.Code, w.Body.String())
	}
	var d struct {
		Salons []struct {
			Slug string
			Fils int
		}
	}
	json.Unmarshal(w.Body.Bytes(), &d)
	if len(d.Salons) != 1 || d.Salons[0].Fils != 2 {
		t.Errorf("salons rendus : %+v", d.Salons)
	}
}

func TestUnJetonSansSujetVoitSeulementLePublic(t *testing.T) {
	// Un jeton de service — sans `sub` correspondant a un membre — ne doit pas
	// donner acces aux fils locaux. C'est le meme raisonnement que pour le
	// visiteur anonyme du site.
	srv, _, _ := bancMembre(t)
	w := api(srv, "GET", "/api/v1/bbs/m/fils", jetonPour("inconnu-ici"), "")
	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "Fil local") {
		t.Error("un fil local est rendu a un sujet inconnu")
	}
}

func TestUnMembreVoitLesFilsLocaux(t *testing.T) {
	srv, _, _ := bancMembre(t)
	w := api(srv, "GET", "/api/v1/bbs/m/fils", jetonPour("cedre83"), "")
	if !strings.Contains(w.Body.String(), "Fil local") {
		t.Errorf("le membre ne voit pas les fils locaux : %s", w.Body.String())
	}
}

func TestEcrireDepuisLApplicationEcritSousLeBonNom(t *testing.T) {
	srv, s, uid := bancMembre(t)
	w := api(srv, "POST", "/api/v1/bbs/m/fils/1/reponse", jetonPour("cedre83"),
		`{"corps":"envoye depuis le telephone"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code %d : %s", w.Code, w.Body.String())
	}
	posts, _ := s.PostsOf(1)
	if len(posts) != 2 {
		t.Fatalf("%d messages", len(posts))
	}
	if posts[1].AuthorID != uid {
		t.Errorf("message attribue a %d au lieu de %d", posts[1].AuthorID, uid)
	}
	// PAR DEFAUT LOCAL, comme partout ailleurs : une application mobile ne doit
	// pas publier plus largement que le site.
	if posts[1].Visibility != store.VisLocal {
		t.Errorf("visibilite : %q", posts[1].Visibility)
	}
}

func TestUnSujetInconnuNePeutPasEcrire(t *testing.T) {
	srv, s, _ := bancMembre(t)
	api(srv, "POST", "/api/v1/bbs/m/fils/1/reponse", jetonPour("inconnu-ici"),
		`{"corps":"intrus"}`)
	posts, _ := s.PostsOf(1)
	if len(posts) != 1 {
		t.Error("un sujet inconnu a ecrit dans un fil")
	}
}

func TestUnCompteDesactiveNePeutPlusRienFaire(t *testing.T) {
	// La revocation cote SecuBox desactive le compte ici ; l'API doit s'aligner
	// immediatement, sans attendre l'expiration du jeton.
	srv, s, uid := bancMembre(t)
	s.DisableUser(uid)
	w := api(srv, "GET", "/api/v1/bbs/m/salons", jetonPour("cedre83"), "")
	if w.Code == http.StatusOK {
		t.Error("un compte desactive garde l'acces a l'API")
	}
}
