package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
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
	srv, err := New(s, nil, Options{Titre: "Banc", Secrets: filepath.Join(root, "secrets")})
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

func TestUnMembreConnecteVoitLesFilsLocaux(t *testing.T) {
	// Ce test manquait, et son absence a coute deux defauts reels, trouves par
	// un essai de bout en bout et non par la suite de tests :
	//
	//   1. le gabarit comparait `.V.Role` (type store.Role) a la chaine
	//      "sysop". Les gabarits Go refusent de comparer deux types
	//      differents : le rendu s'arretait la, sur TOUTE page vue par un
	//      membre connecte.
	//
	//   2. l'erreur de gabarit etait avalee en silence et la page PARTIELLE
	//      etait servie avec un code 200. Un defaut de rendu se presentait donc
	//      comme une page vide mais valide.
	//
	// Tous les tests precedents n'exercaient que le chemin anonyme.
	srv, s := banc(t)
	uid, _ := peuple(t, s)
	jeton, _ := s.NewSession(uid, "", "")

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("code %d pour un membre connecte", w.Code)
	}
	body := w.Body.String()
	for _, veut := range []string{"Fil visible de dehors", "Coordonnees privees"} {
		if !strings.Contains(body, veut) {
			t.Errorf("un membre connecte ne voit pas %q", veut)
		}
	}
	// La page doit etre COMPLETE : une erreur de gabarit tronque le document
	// sans que le code HTTP ne change.
	if !strings.Contains(body, "</html>") {
		t.Error("page tronquee — le gabarit a echoue en cours de rendu")
	}
}

func TestUneErreurDeGabaritDonneUn500PasUnePageTronquee(t *testing.T) {
	// Servir un document a moitie ecrit avec un code 200, c'est affirmer que
	// tout va bien en montrant le contraire. Le rendu passe donc par un tampon :
	// soit la page entiere part, soit une erreur franche.
	srv, _ := banc(t)
	w := httptest.NewRecorder()
	srv.rend(w, httptest.NewRequest("GET", "/", nil), "gabarit-inexistant", page{})
	if w.Code == http.StatusOK {
		t.Errorf("un gabarit manquant repond %d", w.Code)
	}
}

func TestOuvrirUnFilDepuisLInterface(t *testing.T) {
	// Le gabarit proposait « Nouveau fil » depuis le debut ; la ROUTE n'a
	// jamais existe. Le bouton menait a une page introuvable — un defaut que
	// seule une visite de l'interface revele, et qu'aucun test ne couvrait
	// puisque tous partaient de fils crees en base.
	srv, s := banc(t)
	uid, _ := peuple(t, s)
	jeton, _ := s.NewSession(uid, "", "")
	csrf := "jeton-de-test-assez-long"

	f := url.Values{
		"csrf": {csrf}, "categorie": {"1"},
		"title": {"Un fil tout neuf"}, "body": {"Le premier message."},
		"visibility": {"public"},
	}
	r := httptest.NewRequest("POST", "/nouveau", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	r.AddCookie(&http.Cookie{Name: cookieCSRF, Value: csrf})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("creation refusee : code %d — %s", w.Code, w.Body.String())
	}
	th, _ := s.Recent(10, false)
	var cree *store.Thread
	for i := range th {
		if th[i].Title == "Un fil tout neuf" {
			cree = &th[i]
		}
	}
	if cree == nil {
		t.Fatalf("le fil n'a pas ete cree : %+v", th)
	}
	if cree.Visibility != store.VisPublic {
		t.Errorf("visibilite : %q", cree.Visibility)
	}
}

func TestUnVisiteurNePeutPasOuvrirDeFil(t *testing.T) {
	srv, s := banc(t)
	peuple(t, s)
	f := url.Values{"categorie": {"1"}, "title": {"Intrus"}, "body": {"x"}}
	r := httptest.NewRequest("POST", "/nouveau", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	// On n'asserte PAS le code : rediriger vers la page de connexion est une
	// reponse legitime, et c'est un 303 comme un succes. Ce qui compte est
	// qu'AUCUN fil n'ait ete ecrit.
	th, _ := s.Recent(20, false)
	for _, x := range th {
		if x.Title == "Intrus" {
			t.Error("un visiteur non connecte a ouvert un fil")
		}
	}
}

func TestLaConsoleSysopEstFermeeAuxNonSysops(t *testing.T) {
	// Le lien /sysop n'apparait que pour un sysop, mais l'ADRESSE est
	// devinable. « Ce n'est pas dans le menu » n'a jamais ferme une porte.
	srv, s := banc(t)
	uid, _ := s.CreateUser("membre", "Membre", store.RoleMember)
	jeton, _ := s.NewSession(uid, "", "")

	r := httptest.NewRequest("GET", "/sysop", nil)
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Errorf("un membre ordinaire atteint la console sysop (code %d)", w.Code)
	}

	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, httptest.NewRequest("GET", "/sysop", nil))
	if w2.Code == http.StatusOK {
		t.Errorf("un visiteur anonyme atteint la console sysop (code %d)", w2.Code)
	}
}

func TestUnSysopAtteintSaConsole(t *testing.T) {
	srv, s := banc(t)
	uid, _ := peuple(t, s)
	jeton, _ := s.NewSession(uid, "", "")
	r := httptest.NewRequest("GET", "/sysop", nil)
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("console refusee au sysop : %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "</html>") {
		t.Error("page tronquee")
	}
}

func TestLesFichiersStatiquesSontRevalides(t *testing.T) {
	// SANS EN-TETE DE CACHE, le navigateur decide seul — et il garde. Une
	// feuille de style servie une fois reste servie longtemps, meme apres
	// plusieurs deploiements : la page s'affiche alors avec un CSS d'une
	// version anterieure, sans erreur, sans indice.
	//
	// C'est ce qui s'est produit : une version de bbs.css momentanement privee
	// de ses classes utilitaires est restee en cache, et la mise en page
	// paraissait cassee alors que le serveur envoyait la bonne feuille.
	//
	// `no-cache` ne veut pas dire « ne pas mettre en cache » mais « revalider
	// avant de reutiliser ». Avec un ETag, la revalidation coute une reponse
	// 304 vide.
	srv, _ := banc(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/static/bbs.css", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("feuille de style absente : %d", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control = %q — le navigateur gardera une version perimee", cc)
	}
	if w.Header().Get("ETag") == "" {
		t.Error("aucun ETag : chaque revalidation retelechargera tout le fichier")
	}
}

func TestLaFeuilleDeStyleEstAppeleeAvecSonEmpreinte(t *testing.T) {
	// LE WAF DE LA BOARD SUPPRIME `Cache-Control` ET `ETag` : verifie sur
	// gk2, la socket et nginx les envoient, sbxwaf ne les transmet pas. Aucun
	// module ne peut donc demander une revalidation au navigateur, qui garde
	// alors ce qu'il a — y compris une feuille de style d'une version
	// anterieure, sans erreur ni indice.
	//
	// Le seul levier qui reste passe par l'ADRESSE : une empreinte du contenu
	// dans la requete. Le fichier change, l'adresse change, le navigateur le
	// considere comme une autre ressource. Cela ne depend d'aucun en-tete.
	srv, _ := banc(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	body := w.Body.String()

	if !strings.Contains(body, "/static/bbs.css?v=") {
		t.Errorf("la feuille est appelee sans empreinte — un cache perime restera")
	}
	if strings.Contains(body, `/static/bbs.css"`) {
		t.Error("appel sans empreinte encore present")
	}
	// L'empreinte doit etre stable d'un rendu a l'autre, sinon le navigateur
	// retelecharge a chaque page et le cache ne sert plus a rien.
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, httptest.NewRequest("GET", "/", nil))
	v1 := entre(body, "/static/bbs.css?v=", `"`)
	v2 := entre(w2.Body.String(), "/static/bbs.css?v=", `"`)
	if v1 == "" || v1 != v2 {
		t.Errorf("empreinte instable : %q puis %q", v1, v2)
	}
}

func entre(s, deb, fin string) string {
	i := strings.Index(s, deb)
	if i < 0 {
		return ""
	}
	r := s[i+len(deb):]
	j := strings.Index(r, fin)
	if j < 0 {
		return ""
	}
	return r[:j]
}

func TestLeHtmlServiEstBienForme(t *testing.T) {
	// UNE BALISE MAL FERMEE NE PRODUIT AUCUNE ERREUR : le navigateur repare a
	// sa maniere, et ce qui suit se retrouve avale par l'element ouvert. Ici
	// une ancre fermee par `</div>` engloutissait le bouton de deconnexion PUIS
	// tout le contenu de la page — un trou de 700 pixels et un bouton egare en
	// bas a gauche.
	//
	// Le defaut n'apparaissait QUE connecte, et toutes mes verifications
	// passaient par des pages anonymes. Ce test parcourt les deux.
	srv, s := banc(t)
	uid, _ := peuple(t, s)
	jeton, _ := s.NewSession(uid, "", "")

	for _, cas := range []struct {
		nom, chemin string
		connecte    bool
	}{
		{"accueil anonyme", "/", false},
		{"accueil connecte", "/", true},
		{"salon connecte", "/c/atelier", true},
		{"fil connecte", "/t/1", true},
		{"compte", "/compte", true},
		{"sysop", "/sysop", true},
		{"nouveau fil", "/nouveau", true},
	} {
		r := httptest.NewRequest("GET", cas.chemin, nil)
		if cas.connecte {
			r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			continue
		}
		if mal := malFormees(w.Body.String()); len(mal) > 0 {
			t.Errorf("%s (%s) : balises mal fermees %v", cas.nom, cas.chemin, mal)
		}
	}
}

// malFormees rend les balises fermees par un nom different de celui ouvert.
func malFormees(h string) []string {
	var pile, mal []string
	vides := map[string]bool{"br": true, "img": true, "input": true, "meta": true,
		"link": true, "hr": true, "source": true}
	for _, m := range baliseRe.FindAllStringSubmatch(h, -1) {
		nom := strings.ToLower(m[2])
		if vides[nom] || strings.HasSuffix(m[0], "/>") {
			continue
		}
		if m[1] == "/" {
			if len(pile) > 0 && pile[len(pile)-1] == nom {
				pile = pile[:len(pile)-1]
			} else {
				mal = append(mal, "</"+nom+">")
			}
			continue
		}
		pile = append(pile, nom)
	}
	for _, n := range pile {
		mal = append(mal, "<"+n+"> jamais ferme")
	}
	return mal
}

var baliseRe = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>`)
