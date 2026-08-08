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
	"strings"

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
}

type Source struct {
	Nom        string
	Categorie  int64
	Auteur     int64
	Visibilite store.Visibility
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
		cree, maj, err := s.UpsertSourced(src.Categorie, src.Auteur, it.Titre, corps, vis,
			src.Nom, it.Ref, it.Date)
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
