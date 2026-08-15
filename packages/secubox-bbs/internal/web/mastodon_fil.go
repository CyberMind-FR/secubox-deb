package web

// Fil distant du compte lie (#1044).
//
// POURQUOI UN CACHE, ET PAS UN SIMPLE APPEL. La page `/mastodon` est une page
// comme les autres : on y arrive, on repart, on y revient. Interroger
// l'instance a chaque affichage ferait dependre le temps de reponse du BBS de
// celui d'un serveur tiers — et sur un fil de 20 publications, la difference
// entre 40 ms et 6 s est celle entre une page et une attente.
//
// LE CACHE EST PAR MEMBRE, jamais global : deux membres ne lient pas le meme
// compte, et un cache partage servirait le fil de l'un a l'autre.

import (
	"context"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/mastodon"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
	"net/url"
	"strings"
)

// DureeFilMastodon : au-dela, le fil est redemande.
//
// 90 s : assez court pour qu'une publication recente apparaisse sans avoir a
// attendre, assez long pour qu'un rechargement de page n'appelle pas l'instance.
const DureeFilMastodon = 90 * time.Second

// DelaiFilMastodon borne l'attente. Plus court que le delai general du client
// (12 s) : ici on prefere une page sans fil a une page qui met dix secondes.
const DelaiFilMastodon = 5 * time.Second

// PublicationVue : une entree du fil, prete a afficher.
//
// `Texte` EST DU TEXTE BRUT, jamais du HTML — voir `mastodon.TexteDe`. Le
// marquer `template.HTML` rendrait a une instance tierce le droit d'executer du
// script chez nos membres.
type PublicationVue struct {
	Texte    string
	Avert    string
	Sensible bool
	URL      string
	Quand    string
	Medias   []MediaVue
	Reponses int
	Partages int
	Favoris  int
}

// MediaVue : une piece jointe, et surtout la reponse a « peut-on la charger ».
//
// `Interne` DECIDE SI L'IMAGE S'AFFICHE OU RESTE UN LIEN.
//
// Charger une image distante signale la lecture au serveur qui la sert : sur
// une publication federee, ce serveur est celui d'un inconnu, et chaque
// affichage de la page lui dirait qui regarde, quand, depuis quelle adresse.
//
// MAIS CE FIL EST CELUI DU MEMBRE, sur SON instance — souvent la notre, sur
// cette meme machine. Lui refuser ses propres images au nom d'une fuite vers
// lui-meme ne protegeait personne, et rendait la page vide : ses publications
// n'ont pas de texte, l'image EST le contenu.
//
// On tranche donc par l'hote : ce que sert l'instance du compte s'affiche, le
// reste demeure un lien.
type MediaVue struct {
	mastodon.Media
	Interne bool
}

type filCache struct {
	pris time.Time
	fil  []PublicationVue
	err  error
}

var (
	filMu sync.Mutex
	fils  = map[int64]filCache{}
)

// filMastodon rend le fil du compte lie a CE membre.
//
// L'ERREUR N'EST PAS FATALE : une instance injoignable doit laisser la page
// s'afficher, avec une ligne qui le dit. Perdre le fil est un desagrement,
// perdre la page une panne.
func (s *Server) filMastodon(userID int64, c store.CompteMastodon) ([]PublicationVue, error) {
	filMu.Lock()
	if e, ok := fils[userID]; ok && time.Since(e.pris) < DureeFilMastodon {
		filMu.Unlock()
		return e.fil, e.err
	}
	filMu.Unlock()

	fil, err := s.chercheFil(c)

	filMu.Lock()
	// LE CACHE RETIENT AUSSI L'ECHEC. Sans cela, une instance en panne serait
	// re-interrogee a chaque affichage, et chaque page attendrait le delai
	// complet — la panne d'en face deviendrait la notre.
	fils[userID] = filCache{pris: time.Now(), fil: fil, err: err}
	filMu.Unlock()
	return fil, err
}

func (s *Server) chercheFil(c store.CompteMastodon) ([]PublicationVue, error) {
	cli, err := s.clientMastodon(c.Instance)
	if err != nil {
		return nil, err
	}
	ctx, annule := context.WithTimeout(context.Background(), DelaiFilMastodon)
	defer annule()

	pubs, err := cli.StatutsDuCompte(ctx, c.CompteID, 12)
	if err != nil {
		return nil, err
	}
	out := make([]PublicationVue, 0, len(pubs))
	for _, p := range pubs {
		texte := mastodon.TexteDe(p.Contenu)
		if texte == "" && len(p.Medias) == 0 {
			continue // une publication vide n'apprend rien
		}
		medias := make([]MediaVue, 0, len(p.Medias))
		for _, m := range p.Medias {
			medias = append(medias, MediaVue{Media: m, Interne: servePar(m, c.Instance)})
		}
		out = append(out, PublicationVue{
			Texte: texte, Avert: p.Avert, Sensible: p.Sensible,
			URL: p.URL, Quand: quandCourt(p.CreeLe), Medias: medias,
			Reponses: p.Reponses, Partages: p.Partages, Favoris: p.Favoris,
		})
	}
	return out, nil
}

// servePar dit si une piece jointe vient bien de l'instance du compte.
//
// COMPARAISON D'HOTE, jamais de prefixe de chaine : `social.exemple.fr` et
// `social.exemple.fr.pirate.net` partagent un prefixe et pas un hote. C'est
// l'erreur classique de ce genre de controle.
func servePar(m mastodon.Media, instance string) bool {
	adr := m.Apercu
	if adr == "" {
		adr = m.URL
	}
	u, err := url.Parse(adr)
	if err != nil || u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Hostname(), strings.TrimSpace(instance))
}

// oublieFilMastodon vide le cache d'un membre.
//
// Appele au deliement : sans cela, le fil de l'ancien compte resterait affiche
// jusqu'a 90 s apres qu'on l'a retire — ce qui donnerait a croire que le
// retrait n'a pas pris.
func oublieFilMastodon(userID int64) {
	filMu.Lock()
	delete(fils, userID)
	filMu.Unlock()
}

// quandCourt rend une date ISO en jour/mois/heure, ou la chaine d'origine si
// elle ne se lit pas — on n'invente pas une date qu'on n'a pas comprise.
func quandCourt(iso string) string {
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return iso
	}
	return t.Local().Format("02/01 15:04")
}
