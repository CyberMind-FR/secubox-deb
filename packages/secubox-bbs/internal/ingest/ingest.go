// Package ingest alimente le BBS depuis les autres modules.
//
// TROIS SOURCES, UN SEUL CHEMIN : billets (archives), PeerTube (vidéos) et le
// podcaster (épisodes) produisent des Item ; Importer les transforme en fils.
// Ce qui differe entre les sources est la LECTURE, jamais l'ecriture — sans
// quoi chaque passerelle reinventerait sa propre idee de l'identite, et l'une
// d'elles se tromperait.
//
// LE MEDIA N'EST PAS RECOPIE. Un fil importe porte un LIEN vers l'episode ou la
// video la ou ils sont deja. Dupliquer 400 Mo par episode remplirait le disque
// pour rien, et il faudrait ensuite decider laquelle des deux copies fait foi.
package ingest

import (
	"fmt"
	"os"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// Item : ce qu'une source rend, apres normalisation.
type Item struct {
	// Ref identifie l'objet CHEZ LA SOURCE et ne change jamais : identifiant
	// PeerTube, GUID d'episode, identifiant de billet. Jamais le titre.
	Ref   string
	Titre string
	Corps string
	Lien  string
	Date  int64
	// Media : adresse JOUABLE. Pour une video, l'adresse d'integration ; pour
	// un episode, celle que le BBS sert lui-meme depuis le fichier deja
	// telecharge — pas l'enclosure d'origine, qui enverrait chaque auditeur
	// chez un tiers.
	Media string
	Kind  string
	// Vignette : URL du POSTER (image) chez la source — pochette d'épisode,
	// miniature PeerTube. #1049 : la mosaïque la relaie localement (jamais
	// l'hôte tiers). Vide = pas de poster, la tuile montre un glyphe.
	Vignette string
}

type Source struct {
	Nom        string
	Categorie  int64
	Auteur     int64
	Visibilite store.Visibility
	// Noeud : identité du nœud d'origine pour la passerelle (#1049). Vide =
	// nom d'hôte de la board.
	Noeud string
}

type Resultat struct {
	Vus, Crees, Ignores int
	MisAJour            int
	Erreurs             []string
}

// Importer cree un fil par item encore inconnu.
//
// IDEMPOTENT PAR CONSTRUCTION : l'unicite de (source, ref) est portee par un
// index de la BASE, pas par une verification prealable. Une verification
// prealable laisse une fenetre entre le SELECT et l'INSERT ; deux imports
// lances en meme temps — une minuterie et une relance manuelle — passeraient
// tous les deux.
func Importer(s *store.Store, src Source, items []Item) (Resultat, error) {
	var r Resultat
	vis := src.Visibilite
	if vis != store.VisPublic {
		// AU DOUTE, LOCAL. Une passerelle publie sans relecture humaine : se
		// tromper vers « public » met sur internet une liste de titres que
		// personne n'a decide de publier, et cela ne se rattrape pas.
		vis = store.VisLocal
	}

	// #1049 — nœud d'origine (nom d'hôte par défaut) et propriété : le contenu
	// public de la boîte est « soi » (republiable), le local reste « tiers ».
	noeud := src.Noeud
	if noeud == "" {
		if h, herr := os.Hostname(); herr == nil {
			noeud = h
		} else {
			noeud = "local"
		}
	}
	propriete := gateway.ProprieteTiers
	if src.Visibilite == store.VisPublic {
		propriete = gateway.ProprieteSoi
	}

	for _, it := range items {
		r.Vus++
		if strings.TrimSpace(it.Ref) == "" {
			// Sans reference, aucune identite : l'item serait recree a chaque
			// passage. On le laisse de cote plutot que de l'importer une fois
			// par execution.
			r.Ignores++
			r.Erreurs = append(r.Erreurs, "item sans reference : "+bref(it.Titre))
			continue
		}
		corps := it.Corps
		if it.Lien != "" {
			corps = strings.TrimRight(corps, "\n") + "\n\n[Voir chez " + src.Nom + "](" + it.Lien + ")\n"
		}
		cree, maj, err := s.UpsertSourcedMedia(src.Categorie, src.Auteur, it.Titre, corps, vis,
			src.Nom, it.Ref, it.Date, it.Media, it.Kind)
		switch {
		case err != nil:
			// UN ITEM DEFECTUEUX N'INTERROMPT PAS LES AUTRES. Un import qui
			// s'arrete au premier defaut laisse la moitie du catalogue dehors,
			// et il faut deviner laquelle.
			r.Ignores++
			r.Erreurs = append(r.Erreurs, fmt.Sprintf("%s : %v", bref(it.Titre), err))
		case cree:
			r.Crees++
		case maj:
			r.MisAJour++
			r.Ignores++
		default:
			r.Ignores++ // deja connu — le cas NORMAL a partir du second passage
		}

		// #1049 — peuple AUSSI la passerelle (gateway_contenu), que GatewayRecents
		// relit pour la mosaïque. Best-effort : un Contenu invalide (adresse
		// manquante…) est ignoré sans casser l'import du forum ci-dessus. La
		// déduplication par empreinte rend l'appel idempotent d'un passage à l'autre.
		c := ContenuDepuisItem(it, src.Nom, noeud, propriete)
		if _, gerr := s.GatewayEnregistrer(c); gerr != nil {
			r.Erreurs = append(r.Erreurs, fmt.Sprintf("passerelle %s : %v", bref(it.Titre), gerr))
		}
	}

	if err := s.LogIngest(src.Nom, r.Vus, r.Crees, r.Ignores, strings.Join(r.Erreurs, " | ")); err != nil {
		return r, err
	}
	return r, nil
}

func bref(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 60 {
		return s[:60] + "…"
	}
	if s == "" {
		return "(sans titre)"
	}
	return s
}
