package web

import (
	"html"
	"regexp"
	"strings"
	"sync"
)

// originesFiche : les services dont un lien devient une fiche.
//
// VARIABLE DE PAQUET, ET C'EST UN CHOIX. `Render` est appelee depuis les
// gabarits, sans porteur d'options ; lui en ajouter un aurait touche chaque
// appel de rendu du module pour une seule fonctionnalite. La liste est posee
// une fois au demarrage et ne change plus.
var (
	originesFicheMu sync.RWMutex
	originesFiche   []string
)

// ConfigurerFiches declare les services reconnus. Appelee au demarrage.
//
// Vide, aucun lien ne devient une fiche : les adresses restent des liens
// ordinaires. C'est le bon defaut — une autre installation n'a pas nos vhosts.
func ConfigurerFiches(origines []string) {
	originesFicheMu.Lock()
	defer originesFicheMu.Unlock()
	originesFiche = nil
	for _, o := range origines {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			originesFiche = append(originesFiche, strings.ToLower(o))
		}
	}
}

// ancreRe capture une ancre deja produite par `liens()` ou `adressesNues()`.
//
// ON TRAVAILLE SUR L'ANCRE, pas sur le texte brut : a ce stade tout est deja
// echappe, et reconnaitre l'adresse nue rejouerait le travail de deux etapes
// precedentes — avec le risque d'agir a l'interieur d'un `href` qu'on vient de
// produire.
var ancreRe = regexp.MustCompile(`<a href="(https://[^"]+)"[^>]*>([^<]*)</a>`)

// serviceDe rend le nom court du service, ou "" si l'origine n'est pas connue.
func serviceDe(adresse string) string {
	originesFicheMu.RLock()
	defer originesFicheMu.RUnlock()
	bas := strings.ToLower(adresse)
	for _, o := range originesFiche {
		// Le separateur compte : sans lui, `https://radio.gk2.secubox.in.mal.tld`
		// serait pris pour notre radio.
		if bas == o || strings.HasPrefix(bas, o+"/") {
			hote := strings.TrimPrefix(o, "https://")
			if i := strings.IndexByte(hote, '.'); i > 0 {
				return hote[:i]
			}
			return hote
		}
	}
	return ""
}

// fichesSecuBox transforme un lien vers un de NOS services en fiche.
//
// AUCUN APPEL RESEAU AU RENDU. Interroger le service pour son titre ferait,
// sur un fil de trente liens, trente requetes avant que la page ne parte — et
// un service lent bloquerait l'affichage d'une conversation qui ne le concerne
// pas. La fiche porte ce qu'on sait sans demander : le service et l'adresse.
// Le titre et la vignette viendront d'un enrichissement differe.
//
// Le lien reste un lien : la fiche l'habille, elle ne le remplace pas. Un
// membre dont le service est momentanement absent garde une adresse cliquable.
func fichesSecuBox(s string) string {
	originesFicheMu.RLock()
	vide := len(originesFiche) == 0
	originesFicheMu.RUnlock()
	if vide {
		return s
	}
	return ancreRe.ReplaceAllStringFunc(s, func(tout string) string {
		m := ancreRe.FindStringSubmatch(tout)
		if m == nil {
			return tout
		}
		adresse, texte := m[1], m[2]
		svc := serviceDe(adresse)
		if svc == "" {
			return tout
		}
		if strings.TrimSpace(texte) == "" {
			texte = adresse
		}
		// `adresse` et `texte` viennent d'un HTML deja echappe ; on les
		// reechappe pour l'attribut `title`, ou une apostrophe suffirait a
		// sortir du contexte.
		return `<a class="fiche-sbx" href="` + adresse + `" title="` +
			html.EscapeString(html.UnescapeString(texte)) + `">` +
			`<span class="fiche-svc">` + html.EscapeString(svc) + `</span>` +
			`<span class="fiche-txt">` + texte + `</span></a>`
	})
}
