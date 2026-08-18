// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package gateway

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Resolveur transforme un lien collé en objet, en le confiant au connecteur
// qui le reconnaît. Ce qu'aucun connecteur ne reconnaît devient une carte
// « lien » générique — jamais un refus : l'utilisateur colle, quelque chose
// apparaît.
type Resolveur struct {
	registre *Registre
	noeud    string
}

// NouveauResolveur construit le résolveur sur un registre de connecteurs.
func NouveauResolveur(r *Registre, noeud string) *Resolveur {
	return &Resolveur{registre: r, noeud: noeud}
}

// Resoudre route l'URL vers son connecteur, ou rend une carte générique.
func (rs *Resolveur) Resoudre(u string) (Contenu, error) {
	u = strings.TrimSpace(u)
	if u == "" {
		return Contenu{}, fmt.Errorf("résolveur : adresse vide")
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return Contenu{}, fmt.Errorf("résolveur : adresse illisible : %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return Contenu{}, fmt.Errorf("résolveur : schéma refusé : %q", parsed.Scheme)
	}

	// Tous() rend les connecteurs dans l'ordre de leurs noms : deux connecteurs
	// qui reconnaîtraient la même URL sont donc départagés de façon
	// reproductible, jamais au hasard de la carte.
	for _, c := range rs.registre.Tous() {
		if reconnait(c.Manifeste(), u) {
			// Le connecteur est trouvé : on lui confie l'URL et on remonte SON
			// erreur telle quelle. Retomber sur la carte générique masquerait
			// un cookie périmé ou une plateforme en panne derrière une carte
			// creuse — un mensonge plus nuisible que l'échec.
			return c.Resoudre(u)
		}
	}
	return rs.carteGenerique(parsed), nil
}

// reconnait dit si l'un des motifs du manifeste s'applique à l'URL.
//
// Les motifs ont été validés à l'enregistrement (T4) : ils compilent forcément.
// On ignore malgré tout une compilation ratée par prudence — un connecteur
// muet vaut mieux qu'un résolveur qui panique.
func reconnait(m Manifeste, u string) bool {
	for _, motif := range m.MotifsURL {
		re, err := regexp.Compile(motif)
		if err != nil {
			continue
		}
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

// carteGenerique fabrique la carte d'un lien que personne ne sait mieux traiter.
//
// Sans réseau : résoudre l'inconnu ne doit pas partir chercher une page qui
// pourrait être lente, lourde ou hostile. On garde l'adresse — toujours — et
// on prend l'hôte comme titre, repère lisible à défaut de mieux. La propriété
// est TIERS : on ne présume jamais que ce qu'on ne connaît pas appartient à
// l'utilisateur.
func (rs *Resolveur) carteGenerique(u *url.URL) Contenu {
	titre := u.Hostname()
	if titre == "" {
		titre = u.String()
	}
	return Contenu{
		Genre:        GenreLien,
		Titre:        titre,
		SourceURL:    u.String(),
		Connecteur:   "generique",
		Propriete:    ProprieteTiers,
		NoeudOrigine: rs.noeud,
	}
}
