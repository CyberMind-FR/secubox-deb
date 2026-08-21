package web

import (
	"bytes"
	"fmt"
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

func TestUneReinitialisationVideEstRefusee(t *testing.T) {
	// La longueur minimale a ete retiree ; le mot de passe VIDE reste refuse.
	// Ce n'est pas une limite de longueur mais la difference entre avoir un mot
	// de passe et ne pas en avoir.
	srv, _, _, jGk2, amie, _ := bancMP(t)
	csrf := csrfDe(t, srv, "/sysop", jGk2)
	w := demande(t, srv, "POST", "/sysop/motdepasse", jGk2, url.Values{
		"csrf": {csrf}, "id": {itoa(amie)}, "nouveau": {""},
	})
	if !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Error("mot de passe vide accepte")
	}
	if srv.auth.Verify(amie, "") {
		t.Error("un mot de passe vide a ete pose")
	}
}

func TestLaCoquilleRendSesTroisColonnesEtSaLigneDEtat(t *testing.T) {
	// La disposition ne se verifie pas a l'oeil : un gabarit peut rendre du HTML
	// valide et n'avoir aucune des zones attendues. Ce test fixe le CONTRAT de
	// la coquille — c'est lui qui dira si une modification future la demonte.
	srv, s := banc(t)
	uid, _ := peuple(t, s)
	jeton, _ := s.NewSession(uid, "", "")

	// Depuis #1114 le FIL porte le skin NEWSROOM (define "fil") : masthead
	// partage, rails gauche/droite, et le corps du fil REUTILISE tel quel. Le
	// contrat n'est plus la coquille a trois colonnes de layout.html mais la
	// coquille newsroom — c'est ce que ce test fixe desormais.
	w := demande(t, srv, "GET", "/t/1", jeton, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("fil : code %d", w.Code)
	}
	corps := w.Body.String()
	for _, zone := range []string{
		`class="mast"`,   // masthead partage (avmast)
		`class="wrap"`,   // conteneur trois colonnes newsroom
		`class="rail"`,   // rails gauche + droite
		`class="feed"`,   // colonne centrale
		`class="post`,    // le corps du fil, reutilise
		`newsroom.css`,   // la feuille newsroom l'emporte
		`Derniers billets`, // rail de droite partage (avrail)
	} {
		if !strings.Contains(corps, zone) {
			t.Errorf("zone absente de la coquille newsroom : %s", zone)
		}
	}
	// L'alerte messagerie est le point d'entree /mp du masthead newsroom.
	if !strings.Contains(corps, `class="ibtn mpal`) {
		t.Error("l'alerte messagerie (mpal) est absente du masthead")
	}

	// Une page autonome (compte) porte la MEME coquille newsroom, sans colonne
	// de liste de fils.
	w = demande(t, srv, "GET", "/compte", jeton, nil)
	cc := w.Body.String()
	if !strings.Contains(cc, `class="mast"`) || !strings.Contains(cc, `class="feed"`) {
		t.Error("/compte ne porte pas la coquille newsroom")
	}
	if strings.Contains(cc, `class="liste"`) {
		t.Error("colonne de liste rendue sur une page qui n'a aucun fil")
	}
}

func TestLaMessagerieUtiliseLaColonneDeLaCoquille(t *testing.T) {
	// Elle avait sa PROPRE grille a deux colonnes, imbriquee dans la vue : deux
	// dispositions superposees, chacune reprenant la moitie de la place, et la
	// conversation finissait dans un quart d'ecran. Ce test empeche qu'une
	// seconde grille reapparaisse.
	srv, _, _, jGk2, _, jAmie := bancMP(t)
	csrf := csrfDe(t, srv, "/mp/amie", jGk2)
	demande(t, srv, "POST", "/mp/envoyer", jGk2, url.Values{
		"csrf": {csrf}, "vers": {"amie"}, "corps": {"un mot"},
	})

	w := demande(t, srv, "GET", "/mp/gk2", jAmie, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	corps := w.Body.String()

	// Depuis #1114 la messagerie porte le skin newsroom (define "mpnr") : les
	// conversations occupent le RAIL GAUCHE partage, en entrees `.rub.conv` — le
	// « menu » du module, dans la coquille, pas une seconde grille imbriquee.
	if !strings.Contains(corps, `class="mast"`) || !strings.Contains(corps, `class="feed"`) {
		t.Error("/mp ne porte pas la coquille newsroom")
	}
	if !strings.Contains(corps, `class="rub conv`) {
		t.Error("aucune entree de conversation dans le rail")
	}
	// L'interlocuteur ouvert est signale, comme un fil ouvert l'est.
	if !strings.Contains(corps, `aria-current="page"`) {
		t.Error("la conversation ouverte n'est pas marquee")
	}
	// AUCUNE seconde grille imbriquee : c'est le defaut qu'on interdit toujours.
	if strings.Contains(corps, `class="mp"`) || strings.Contains(corps, "mp-liste") {
		t.Error("une seconde disposition est reapparue dans la vue")
	}
}

func TestLAnnuaireRemplaceLeMurDePastilles(t *testing.T) {
	// La colonne listait TOUS les comptes ouverts en pastilles : tenable a cinq
	// membres, illisible a cinquante. Elle montre desormais le CARNET, et
	// l'annuaire complet est une recherche sur sa propre page.
	srv, s, _, jGk2, _, _ := bancMP(t)
	for _, h := range []string{"paul", "pauline", "pierre"} {
		s.CreateUser(h, h, store.RoleMember)
	}

	// La recherche rend ce qu'on cherche, et rien d'autre.
	w := demande(t, srv, "GET", "/mp/annuaire?q=paul", jGk2, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("annuaire : code %d", w.Code)
	}
	corps := w.Body.String()
	if !strings.Contains(corps, "pauline") || !strings.Contains(corps, ">paul<") {
		t.Error("la recherche ne rend pas les correspondances attendues")
	}
	if strings.Contains(corps, "pierre") {
		t.Error("la recherche rend un membre qui ne correspond pas")
	}

	// Ajouter au carnet, puis le retrouver dans la colonne.
	csrf := csrfDe(t, srv, "/mp/annuaire", jGk2)
	w = demande(t, srv, "POST", "/mp/carnet", jGk2, url.Values{
		"csrf": {csrf}, "qui": {"paul"}, "note": {"le voisin"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("ajout au carnet : code %d", w.Code)
	}
	w = demande(t, srv, "GET", "/mp", jGk2, nil)
	if !strings.Contains(w.Body.String(), "le voisin") {
		t.Error("le contact ajoute n'apparait pas dans la colonne")
	}
	// ET SURTOUT : la colonne ne liste plus tout le monde.
	if strings.Contains(w.Body.String(), "pierre") {
		t.Error("la colonne liste encore les comptes hors carnet")
	}
}

func TestUnInterlocuteurActifNEstJamaisAnnonceFerme(t *testing.T) {
	// REGRESSION VECUE. L'etat de l'interlocuteur etait DEDUIT d'une liste :
	// absent de « tous les comptes joignables » ⇒ repute ferme. Le jour ou
	// cette liste a ete remplacee par le carnet, tout interlocuteur hors carnet
	// s'est retrouve annonce ferme, formulaire d'envoi retire — sur des comptes
	// parfaitement actifs.
	//
	// Une absence dans une liste ne prouve rien sur un compte.
	srv, s, _, jGk2, _, _ := bancMP(t)
	s.CreateUser("horscarnet", "Hors Carnet", store.RoleMember)

	w := demande(t, srv, "GET", "/mp/horscarnet", jGk2, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("code %d", w.Code)
	}
	corps := w.Body.String()
	if strings.Contains(corps, "compte est fermé") || strings.Contains(corps, "compte fermé") {
		t.Error("un compte actif est annonce comme ferme")
	}
	// Et le formulaire d'envoi est bien la : c'est ce que la fausse mention
	// retirait.
	if !strings.Contains(corps, `action="/mp/envoyer"`) {
		t.Error("le formulaire d'envoi est absent pour un compte actif")
	}

	// A l'inverse, un compte REELLEMENT ferme est signale, et sans formulaire.
	ferme, _ := s.CreateUser("parti", "Parti", store.RoleMember)
	s.DisableUser(ferme)
	w = demande(t, srv, "GET", "/mp/parti", jGk2, nil)
	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), `action="/mp/envoyer"`) {
		t.Error("formulaire d'envoi propose vers un compte ferme")
	}
}

func TestLAvatarApparaitPartoutOuUnMembreEstNomme(t *testing.T) {
	// Un avatar pose sur son compte et visible nulle part ailleurs ne sert a
	// rien : c'est aux endroits ou l'on croise les AUTRES qu'il porte
	// l'information — un fil, une conversation, l'annuaire.
	srv, s, gk2, jGk2, amie, _ := bancMP(t)

	// gk2 se donne un avatar.
	f, err := s.DeposeFichier(gk2, "moi.png", "image/png",
		bytes.NewReader(append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PoseAvatar(gk2, f.ID); err != nil {
		t.Fatal(err)
	}
	attendu := fmt.Sprintf(`src="/f/%d"`, f.ID)

	// 1. Dans un fil : gk2 est l'auteur des messages semes par `peuple`.
	w := demande(t, srv, "GET", "/t/1", jGk2, nil)
	if w.Code == http.StatusOK && !strings.Contains(w.Body.String(), attendu) {
		t.Error("avatar absent du fil")
	}

	// 2. Dans l'annuaire, vu par quelqu'un d'autre.
	jAmie2, _ := s.NewSession(amie, "", "")
	w = demande(t, srv, "GET", "/mp/annuaire?q=gk2", jAmie2, nil)
	if !strings.Contains(w.Body.String(), attendu) {
		t.Error("avatar absent de l'annuaire")
	}

	// 3. Dans la colonne des conversations, apres un echange.
	csrf := csrfDe(t, srv, "/mp/amie", jGk2)
	demande(t, srv, "POST", "/mp/envoyer", jGk2, url.Values{
		"csrf": {csrf}, "vers": {"amie"}, "corps": {"bonjour"},
	})
	w = demande(t, srv, "GET", "/mp", jAmie2, nil)
	if !strings.Contains(w.Body.String(), attendu) {
		t.Error("avatar absent de la colonne des conversations")
	}

	// 4. UN AVATAR SUPPRIME REND LES INITIALES, pas une image cassee.
	if err := s.SupprimeFichier(gk2, f.ID); err != nil {
		t.Fatal(err)
	}
	w = demande(t, srv, "GET", "/mp/annuaire?q=gk2", jAmie2, nil)
	if strings.Contains(w.Body.String(), attendu) {
		t.Error("l'avatar supprime est encore servi")
	}
}
