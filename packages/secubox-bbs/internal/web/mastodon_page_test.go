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
