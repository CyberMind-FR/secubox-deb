package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/mastodon"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// RENDU REEL DE LA PAGE, avec un compte lie et un fil connu.
//
// Les tests precedents lisaient le GABARIT ; ils ne pouvaient donc pas voir
// qu'une publication sans texte ne rendait rien du tout a l'ecran. Celui-ci
// rend la page pour de vrai et regarde ce qui en sort.
func pageMastodon(t *testing.T, fil []PublicationVue) string {
	t.Helper()
	srv, s := banc(t)
	uid, err := s.CreateUser("gk2", "Gandalf", store.RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LieCompteMastodon(uid, store.CompteMastodon{
		Instance: "social.exemple.fr", Acct: "gk2", CompteID: "42",
	}, "jeton"); err != nil {
		t.Fatal(err)
	}
	// On garnit le cache : la page ne doit appeler aucune instance en test.
	filMu.Lock()
	fils[uid] = filCache{pris: time.Now(), fil: fil}
	filMu.Unlock()
	t.Cleanup(func() { oublieFilMastodon(uid) })

	jeton, _ := s.NewSession(uid, "", "")
	r := httptest.NewRequest("GET", "/mastodon", nil)
	r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/mastodon repond %d", w.Code)
	}
	return w.Body.String()
}

// LE CAS REEL DU COMPTE gk2 : des publications SANS AUCUN TEXTE, une image
// chacune. C'est exactement ce que rend l'instance, et c'est ce qui
// n'apparaissait pas a l'ecran.
func TestUnePublicationSansTexteAfficheQuandMemeSonMedia(t *testing.T) {
	html := pageMastodon(t, []PublicationVue{{
		Texte: "", Quand: "15/08 14:51",
		URL: "https://social.exemple.fr/@gk2/1",
		Medias: []MediaVue{{Media: mastodon.Media{
			Type: "image", URL: "https://social.exemple.fr/m/1.png"}, Interne: true}},
	}})
	if !strings.Contains(html, "15/08 14:51") {
		t.Error("la date de la publication n'est pas rendue")
	}
	if !strings.Contains(html, "https://social.exemple.fr/m/1.png") {
		t.Error("LE MEDIA N'EST PAS RENDU : une publication sans texte n'affiche rien")
	}
	// L'IMAGE S'AFFICHE, elle n'est plus une pastille : ces publications n'ont
	// pas de texte, l'image EST le contenu, et une pastille « image » ne
	// montrait rien.
	if !strings.Contains(html, "<img src=") {
		t.Error("le media interne n'est pas affiche, seulement lie")
	}
	if !strings.Contains(html, `loading="lazy"`) {
		t.Error("l'image est chargee sans differe")
	}
	if strings.Contains(html, "Aucune publication publique") {
		t.Error("la page annonce un fil vide alors qu'il ne l'est pas")
	}
}

func TestUnePublicationAvecTexteRendSonTexte(t *testing.T) {
	html := pageMastodon(t, []PublicationVue{{
		Texte: "bonjour le fedivers", Quand: "15/08 10:00",
		URL: "https://social.exemple.fr/@gk2/2",
	}})
	if !strings.Contains(html, "bonjour le fedivers") {
		t.Error("le texte de la publication n'est pas rendu")
	}
}

// LE TEXTE EST ECHAPPE, PAS INTERPRETE. Ce qui vient d'une instance tierce ne
// doit jamais devenir du balisage actif dans notre page.
func TestLeTexteDistantEstEchappeDansLaPageRendue(t *testing.T) {
	html := pageMastodon(t, []PublicationVue{{
		Texte: `<script>alert(1)</script>`, Quand: "15/08 09:00",
		URL: "https://social.exemple.fr/@gk2/3",
	}})
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("le texte distant est rendu comme du balisage actif")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("le texte distant n'apparait pas echappe")
	}
}

// UN FIL VIDE LE DIT, et n'affiche pas une carte muette.
func TestUnFilVideLeDit(t *testing.T) {
	html := pageMastodon(t, nil)
	if !strings.Contains(html, "Aucune publication publique") {
		t.Error("un fil vide ne l'annonce pas")
	}
}

// UNE PIECE JOINTE D'UN HOTE TIERS N'EST PAS CHARGEE. Sur une publication
// federee, le serveur qui la sert est celui d'un inconnu : chaque affichage lui
// dirait qui regarde, quand, et depuis quelle adresse.
func TestUnMediaDHoteTiersResteUnLien(t *testing.T) {
	html := pageMastodon(t, []PublicationVue{{
		Texte: "partage", Quand: "15/08 12:00",
		URL: "https://social.exemple.fr/@gk2/9",
		Medias: []MediaVue{{Media: mastodon.Media{
			Type: "image", URL: "https://ailleurs.example/x.png"}, Interne: false}},
	}})
	if strings.Contains(html, `<img src="https://ailleurs.example/x.png"`) {
		t.Error("une image d'un hote tiers serait chargee a l'affichage")
	}
	if !strings.Contains(html, "hôte tiers") {
		t.Error("rien ne signale que la piece jointe vient d'ailleurs")
	}
}

// LA COMPARAISON PORTE SUR L'HOTE, jamais sur un prefixe de chaine :
// `social.exemple.fr` et `social.exemple.fr.pirate.net` partagent un prefixe et
// pas un hote. C'est l'erreur classique de ce genre de controle.
func TestUnHoteQuiImiteLInstanceNestPasInterne(t *testing.T) {
	for _, cas := range []struct {
		adr      string
		attendu  bool
		pourquoi string
	}{
		{"https://social.exemple.fr/m/1.png", true, "l'instance elle-meme"},
		{"https://SOCIAL.EXEMPLE.FR/m/1.png", true, "casse differente"},
		{"https://social.exemple.fr.pirate.net/m/1.png", false, "prefixe trompeur"},
		{"https://pirate.net/social.exemple.fr/1.png", false, "hote dans le chemin"},
		{"http://social.exemple.fr/m/1.png", false, "sans TLS"},
		{"", false, "adresse vide"},
	} {
		got := servePar(mastodon.Media{URL: cas.adr}, "social.exemple.fr")
		if got != cas.attendu {
			t.Errorf("servePar(%q) = %v, attendu %v — %s", cas.adr, got, cas.attendu, cas.pourquoi)
		}
	}
}

// LA POLITIQUE DOIT S'OUVRIR SUR CETTE PAGE, ET SUR ELLE SEULE.
//
// Sans cette ouverture, le navigateur bloque les images et les sons de
// l'instance SANS RIEN DIRE AU SERVEUR : la page part complete, le lecteur
// reste noir, et l'on cherche la panne cote rendu. C'est ce qui s'est produit.
func TestLaPolitiqueSOuvrePourLInstanceLieeSurCettePageSeulement(t *testing.T) {
	srv, s := banc(t)
	uid, err := s.CreateUser("gk2", "Gandalf", store.RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LieCompteMastodon(uid, store.CompteMastodon{
		Instance: "social.exemple.fr", Acct: "gk2", CompteID: "42",
	}, "jeton"); err != nil {
		t.Fatal(err)
	}
	filMu.Lock()
	fils[uid] = filCache{pris: time.Now()}
	filMu.Unlock()
	t.Cleanup(func() { oublieFilMastodon(uid) })
	jeton, _ := s.NewSession(uid, "", "")

	page := func(chemin string) string {
		r := httptest.NewRequest("GET", chemin, nil)
		r.AddCookie(&http.Cookie{Name: cookieSession, Value: jeton})
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w.Header().Get("Content-Security-Policy")
	}

	csp := page("/mastodon")
	if !strings.Contains(csp, "https://social.exemple.fr") {
		t.Errorf("l'instance liee n'est pas autorisee :\n%s", csp)
	}
	for _, d := range []string{"img-src 'self' data: https://social.exemple.fr",
		"media-src 'self' https://social.exemple.fr"} {
		if !strings.Contains(csp, d) {
			t.Errorf("directive attendue absente : %s\n%s", d, csp)
		}
	}
	// L'IMAGE EST AUTORISEE, PAS LE SCRIPT. Confondre les deux est la facon
	// habituelle de vider une politique de son sens.
	i := strings.Index(csp, "script-src")
	j := strings.Index(csp[i:], ";")
	if strings.Contains(csp[i:i+j], "social.exemple.fr") {
		t.Error("l'instance est autorisee a executer du script")
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Error("la politique contient unsafe-inline")
	}

	// LA PORTE SE REFERME : les autres pages gardent la politique stricte.
	if c := page("/"); strings.Contains(c, "social.exemple.fr") {
		t.Errorf("l'accueil herite de l'ouverture :\n%s", c)
	}
}

// UN HOTE MALFORME NE DOIT PAS COUPER LA POLITIQUE EN DEUX. Un navigateur qui
// n'arrive pas a la lire peut l'ignorer ENTIEREMENT — on se croirait protege
// en ne l'etant plus du tout.
func TestUnHoteMalformeNeCassePasLaPolitique(t *testing.T) {
	srv, _ := banc(t)
	for _, mauvais := range []string{
		"exemple.fr; script-src *", "exemple.fr'", `exemple.fr"`,
		"exemple.fr /chemin", "", "   ", "exemple.fr\\x",
	} {
		w := httptest.NewRecorder()
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		srv.OrigineMediaMastodon(w, mauvais)
		got := w.Header().Get("Content-Security-Policy")
		if got != "default-src 'self'" {
			t.Errorf("hote %q a modifie la politique :\n%s", mauvais, got)
		}
	}
}
