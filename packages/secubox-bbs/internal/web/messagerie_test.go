package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// bancMP monte un banc avec deux membres et une session pour chacun.
func bancMP(t *testing.T) (*Server, *store.Store, int64, string, int64, string) {
	t.Helper()
	srv, s := banc(t)
	gk2, _ := peuple(t, s)
	amie, err := s.CreateUser("amie", "Amie", store.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	jGk2, _ := s.NewSession(gk2, "", "")
	jAmie, _ := s.NewSession(amie, "", "")
	return srv, s, gk2, jGk2, amie, jAmie
}

func demande(t *testing.T, srv *Server, methode, chemin, jeton string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if form == nil {
		r = httptest.NewRequest(methode, chemin, nil)
	} else {
		r = httptest.NewRequest(methode, chemin, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if jeton != "" {
		r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	}
	// LE JETON ANTI-REJEU EST COMPARE AU COOKIE, pas a la session : un
	// formulaire poste sans ce cookie recoit un 403, et l'on croirait a tort
	// que la fonctionnalite est refusee. Le navigateur le renvoie tout seul ;
	// ici il faut le poser.
	if v := form.Get("csrf"); v != "" {
		r.AddCookie(&http.Cookie{Name: cookieCSRF, Value: v})
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// csrfDe extrait le jeton CSRF d'une page rendue. Les formulaires en ont
// besoin : sans lui, chaque envoi de test recevrait un 403 et l'on croirait a
// tort que la fonctionnalite est refusee.
func csrfDe(t *testing.T, srv *Server, chemin, jeton string) string {
	t.Helper()
	w := demande(t, srv, "GET", chemin, jeton, nil)
	v := entre(w.Body.String(), `name="csrf" value="`, `"`)
	if v == "" {
		t.Fatalf("aucun jeton CSRF dans %s (code %d)", chemin, w.Code)
	}
	return v
}

func TestLaMessagerieExigeUneSession(t *testing.T) {
	// Une boite de reception accessible sans session serait une fuite directe :
	// les messages prives de tout le monde, servis a qui demande.
	srv, _, _, _, _, _ := bancMP(t)
	for _, chemin := range []string{"/mp", "/mp/amie"} {
		w := demande(t, srv, "GET", chemin, "", nil)
		if w.Code != http.StatusSeeOther {
			t.Errorf("%s anonyme : code %d, attendu une redirection", chemin, w.Code)
		}
	}
}

func TestEnvoyerPuisLireUnMessage(t *testing.T) {
	srv, _, _, jGk2, _, jAmie := bancMP(t)

	csrf := csrfDe(t, srv, "/mp/amie", jGk2)
	w := demande(t, srv, "POST", "/mp/envoyer", jGk2, url.Values{
		"csrf": {csrf}, "vers": {"amie"}, "corps": {"bonjour, on se voit demain"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("envoi : code %d", w.Code)
	}

	// L'AMIE VOIT LE MESSAGE, ET LA PASTILLE DE NON-LUS.
	w = demande(t, srv, "GET", "/mp", jAmie, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("boite de reception : code %d", w.Code)
	}
	corps := w.Body.String()
	if !strings.Contains(corps, "bonjour, on se voit demain") {
		t.Error("le message n'apparait pas dans la boite de reception")
	}
	if mal := malFormees(corps); len(mal) > 0 {
		t.Errorf("balises mal fermees : %v", mal)
	}

	// Ouvrir la conversation la marque lue : le compteur suit ce qui a ete VU.
	w = demande(t, srv, "GET", "/mp/gk2", jAmie, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("conversation : code %d", w.Code)
	}
	if mal := malFormees(w.Body.String()); len(mal) > 0 {
		t.Errorf("conversation, balises mal fermees : %v", mal)
	}
	w = demande(t, srv, "GET", "/", jAmie, nil)
	if strings.Contains(entre(w.Body.String(), `href="/mp"`, `</a>`), "p-new") {
		t.Error("la pastille de non-lus subsiste apres lecture")
	}
}

func TestUnTiersNObtientPasLaConversationParLAdresse(t *testing.T) {
	// Le controle d'acces doit tenir MEME si l'on devine l'adresse. C'est le
	// pendant web du test de magasin : ici on passe par la route reelle.
	srv, s, _, jGk2, _, _ := bancMP(t)
	curieux, _ := s.CreateUser("curieux", "Curieux", store.RoleMember)
	jCurieux, _ := s.NewSession(curieux, "", "")

	csrf := csrfDe(t, srv, "/mp/amie", jGk2)
	demande(t, srv, "POST", "/mp/envoyer", jGk2, url.Values{
		"csrf": {csrf}, "vers": {"amie"}, "corps": {"un propos confidentiel"},
	})

	w := demande(t, srv, "GET", "/mp/amie", jCurieux, nil)
	if strings.Contains(w.Body.String(), "un propos confidentiel") {
		t.Error("un tiers lit la conversation en devinant l'adresse")
	}
}

func TestLEnvoiSansJetonCSRFEstRefuse(t *testing.T) {
	// Sans cette verification, une page tierce ouverte dans le meme navigateur
	// pourrait faire envoyer des messages au nom du membre connecte.
	srv, _, _, jGk2, _, _ := bancMP(t)
	w := demande(t, srv, "POST", "/mp/envoyer", jGk2, url.Values{
		"vers": {"amie"}, "corps": {"envoi force"},
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("code %d, attendu 403", w.Code)
	}
}

func TestUnMembreEmetUneInvitationDepuisSonCompte(t *testing.T) {
	srv, _, _, _, _, jAmie := bancMP(t)
	csrf := csrfDe(t, srv, "/compte", jAmie)

	w := demande(t, srv, "POST", "/compte/invite", jAmie, url.Values{"csrf": {csrf}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("invitation : code %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "code=") {
		t.Fatalf("aucun code emis : %s", loc)
	}
	// Le code est affiche UNE fois, sur la page qui suit la redirection.
	w = demande(t, srv, "GET", loc, jAmie, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("page compte : code %d", w.Code)
	}
	if mal := malFormees(w.Body.String()); len(mal) > 0 {
		t.Errorf("balises mal fermees : %v", mal)
	}
}

func TestLeLienMastodonNEstMontreQuAuxMembres(t *testing.T) {
	// Une invitation Mastodon sert plusieurs fois et ne se revoque pas depuis le
	// BBS : affichee publiquement, elle ouvrirait l'instance a qui passe.
	srv, s, _, _, _, jAmie := bancMP(t)
	s.PoseReglage(store.CleMastodonInstance, "https://social.exemple.fr")
	s.PoseReglage(store.CleMastodonInvite, "https://social.exemple.fr/invite/SECRET")

	w := demande(t, srv, "GET", "/mastodon", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("page anonyme : code %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "invite/SECRET") {
		t.Error("le lien d'invitation est visible sans session")
	}

	w = demande(t, srv, "GET", "/mastodon", jAmie, nil)
	if !strings.Contains(w.Body.String(), "invite/SECRET") {
		t.Error("le lien d'invitation n'apparait pas pour un membre connecte")
	}
	if mal := malFormees(w.Body.String()); len(mal) > 0 {
		t.Errorf("balises mal fermees : %v", mal)
	}
}

func TestUnLienMastodonNonHttpEstRefuse(t *testing.T) {
	// Le lien est rendu dans un href visible de tous les membres. Le refus est
	// pose AU STOCKAGE : une valeur invalide ne doit jamais atteindre la base,
	// sinon elle attend qu'un rendu oublie de la filtrer.
	srv, s, _, jGk2, _, _ := bancMP(t)
	csrf := csrfDe(t, srv, "/sysop", jGk2)

	w := demande(t, srv, "POST", "/sysop/reglages", jGk2, url.Values{
		"csrf": {csrf}, "instance": {"javascript:alert(1)"}, "invitation": {""},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Error("le lien javascript: a ete accepte sans erreur")
	}
	if v, _ := s.Reglage(store.CleMastodonInstance); v != "" {
		t.Errorf("un lien javascript: a ete stocke : %q", v)
	}
}

func TestLeSysopReinitialiseUnMotDePasseEtCoupeLesSessions(t *testing.T) {
	// On reinitialise soit parce que le mot de passe a fuite, soit pour
	// reprendre la main. Dans les deux cas, laisser vivre les sessions ouvertes
	// ailleurs viderait le geste de son sens.
	srv, s, _, jGk2, amie, jAmie := bancMP(t)
	if w := demande(t, srv, "GET", "/compte", jAmie, nil); w.Code != http.StatusOK {
		t.Fatalf("session de l'amie invalide au depart : %d", w.Code)
	}

	csrf := csrfDe(t, srv, "/sysop", jGk2)
	w := demande(t, srv, "POST", "/sysop/motdepasse", jGk2, url.Values{
		"csrf": {csrf}, "id": {itoa(amie)}, "nouveau": {"une-phrase-assez-longue"},
	})
	if !strings.Contains(w.Header().Get("Location"), "msg=") {
		t.Fatalf("reinitialisation refusee : %s", w.Header().Get("Location"))
	}
	if !srv.auth.Verify(amie, "une-phrase-assez-longue") {
		t.Error("le nouveau mot de passe ne fonctionne pas")
	}
	// LA SESSION PRECEDENTE EST MORTE.
	if w := demande(t, srv, "GET", "/compte", jAmie, nil); w.Code == http.StatusOK {
		t.Error("la session ouverte avant la reinitialisation fonctionne encore")
	}
	_ = s
}

func TestUneReinitialisationTropCourteEstRefusee(t *testing.T) {
	// La politique de longueur ne doit pas avoir de porte derobee sur le chemin
	// qu'on emprunte dans l'urgence.
	srv, _, _, jGk2, amie, _ := bancMP(t)
	csrf := csrfDe(t, srv, "/sysop", jGk2)
	w := demande(t, srv, "POST", "/sysop/motdepasse", jGk2, url.Values{
		"csrf": {csrf}, "id": {itoa(amie)}, "nouveau": {"court"},
	})
	if !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Error("mot de passe trop court accepte")
	}
	if srv.auth.Verify(amie, "court") {
		t.Error("le mot de passe court a ete pose malgre le refus")
	}
}
