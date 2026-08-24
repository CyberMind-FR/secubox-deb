package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// mediaMax borne UNE vignette relayee.
//
// La borne porte sur ce qu'on LIT, jamais sur `Content-Length` : cet en-tete
// est declaratif, et un service en panne peut repondre un flux sans fin.
const mediaMax = 2 << 20 // 2 Mio

// mediaDelai : au-dela, la vignette ne vaut plus la connexion qu'elle occupe.
const mediaDelai = 8 * time.Second

// mediaTypes : ce qu'on accepte de rendre.
//
// UN `text/html` RELAYE SERAIT SERVI DEPUIS NOTRE ORIGINE, donc dans notre
// politique de securite — c'est-a-dire avec le droit d'y executer du script.
// Le controle du type n'est pas un confort, c'est la frontiere.
var mediaTypes = map[string]bool{
	"image/jpeg": true, "image/png": true, "image/webp": true,
	"image/gif": true, "image/avif": true,
}

// origineAdmise dit si l'URL vise une origine configuree.
//
// La comparaison porte sur le COUPLE schema+hote, exactement. Comparer le seul
// hote laisserait passer `http://`, et accepter les sous-domaines reviendrait a
// faire confiance a qui sait en creer un.
func origineAdmise(u *url.URL, admises []string) bool {
	if u.Scheme != "https" || u.Host == "" {
		return false
	}
	o := "https://" + strings.ToLower(u.Host)
	for _, a := range admises {
		if strings.EqualFold(strings.TrimRight(strings.TrimSpace(a), "/"), o) {
			return true
		}
	}
	return false
}

// servirMediaVignette relaie la vignette d'un de NOS services.
//
// Chaque service est un vhost distinct du BBS : lier son image ferait contacter
// ce vhost par LE NAVIGATEUR DE CHAQUE MEMBRE, et obligerait a elargir
// `img-src`. Relayer garde la politique fermee et n'apprend rien au service sur
// qui regarde.
func (s *Server) servirMediaVignette(w http.ResponseWriter, r *http.Request) {
	// OUVERT AUX ANONYMES (#1187). Le verrou « reserve aux membres » etait
	// inapproprie : il repondait 403 en invoquant le risque du relais ouvert,
	// alors que CE relais n'est pas ouvert — `origineAdmise` le borne a une
	// liste blanche d'origines configurees, qui sont NOS PROPRES services. Un
	// anonyme ne peut donc faire chercher a la boite que ce qu'elle publie
	// deja. Le verrou ne protegeait rien ; il cassait les vignettes des pages
	// PUBLIQUES, au point qu'on avait fini par ne plus les emettre du tout aux
	// anonymes (cf. enrichirCoversReseaux).
	//
	// Ce qui borne reellement ce relais, et qui reste : liste blanche
	// d'origines, liste blanche de types, 8 s de delai, 2 Mio lus au plus.
	// L'amplification est absorbee par le cache PARTAGE (voir Cache-Control
	// plus bas) : la meme vignette n'est cherchee qu'une fois en amont.
	if len(s.opt.MediaOrigines) == 0 {
		http.NotFound(w, r)
		return
	}
	u, err := url.Parse(r.URL.Query().Get("u"))
	if err != nil || !origineAdmise(u, s.opt.MediaOrigines) {
		// On ne distingue pas les motifs de refus : ce serait offrir un moyen
		// de cartographier la liste et le comportement du relais.
		http.NotFound(w, r)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// AUCUN EN-TETE DU MEMBRE N'EST TRANSMIS — ni cookie, ni referer, ni
	// user-agent. C'est tout l'objet du relais.
	req.Header.Set("Accept", "image/*")
	res, err := (&http.Client{Timeout: mediaDelai}).Do(req)
	if err != nil {
		http.Error(w, "vignette indisponible", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(res.Header.Get("Content-Type"), ";", 2)[0]))
	if !mediaTypes[ct] {
		http.NotFound(w, r)
		return
	}
	corps, err := io.ReadAll(io.LimitReader(res.Body, mediaMax+1))
	if err != nil || len(corps) > mediaMax {
		http.Error(w, "vignette trop volumineuse", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// PUBLIC, pas `private` : aucun en-tete du visiteur n'est transmis en amont,
	// la vignette rendue est identique pour tous. Autoriser le cache partage
	// (nginx / cache media du WAF) est ce qui borne vraiment l'amplification.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(corps)
}
