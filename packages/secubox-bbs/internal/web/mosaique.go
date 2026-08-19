// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Mosaïque de vignettes partagée (#1049).
//
// Un seul composant de présentation pour TOUS les flux — Mastodon, PeerTube,
// podcaster (via RSS), radio, billets. Chaque flux se normalise en gateway.Contenu ;
// la mosaïque en fait des tuiles identiques. La règle qui commande le reste :
// la vignette d'un média distant passe TOUJOURS par un point local (relais ou
// vignette de pièce jointe), jamais l'hôte tiers — sinon chaque affichage lui
// dit qui regarde, quand, et depuis quelle adresse (#1056).
package web

import (
	"net/url"
	"sort"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// TuileMosaique est une carte de la mosaïque : ce qu'il faut pour l'afficher
// sans rien apprendre à l'hôte d'origine.
type TuileMosaique struct {
	Titre      string
	Source     string // badge du connecteur : mastodon, peertube, podcaster, radio, billets
	Lien       string // destination du clic
	Vignette   string // TOUJOURS local : /vignette/<id>.jpg ou /media-vignette?u=…
	Horodatage int64
	Empreinte  string // provenance : jamais fabriquée, jamais réattribuée
}

// vignetteLocale rend l'adresse de vignette d'un média, garantie locale.
//
// Média distant (URL absolue) → relais local ; l'hôte tiers n'est jamais
// contacté par le navigateur du membre. On ne produit une vignette que pour un
// mime que le relais ACCEPTE de servir (mediaTypes, media_relais.go) : viser
// une enclosure audio/vidéo ferait 404 sur un mime refusé et trouerait la grille.
func vignetteLocale(m gateway.Media) string {
	mime := strings.ToLower(strings.TrimSpace(strings.SplitN(m.Mime, ";", 2)[0]))
	if !mediaTypes[mime] {
		return ""
	}
	if u, err := url.Parse(m.Chemin); err == nil && u.IsAbs() && u.Host != "" {
		return "/media-vignette?u=" + url.QueryEscape(m.Chemin)
	}
	return ""
}

// tuileDepuisContenu normalise un Contenu de la passerelle en tuile de mosaïque.
func tuileDepuisContenu(c gateway.Contenu) TuileMosaique {
	t := TuileMosaique{
		Titre:      c.Titre,
		Source:     c.Connecteur,
		Lien:       c.SourceURL,
		Horodatage: c.PublieLe,
		Empreinte:  c.Empreinte,
	}
	for _, m := range c.Medias {
		if v := vignetteLocale(m); v != "" {
			t.Vignette = v
			break
		}
	}
	return t
}

// assemblerMosaique mêle des Contenu de flux hétérogènes en une grille : ordre
// par le temps (plus récent d'abord), bornée à `max` tuiles. Un `max` ≤ 0 ne
// borne pas.
func assemblerMosaique(contenus []gateway.Contenu, max int) []TuileMosaique {
	tries := make([]gateway.Contenu, len(contenus))
	copy(tries, contenus)
	sort.SliceStable(tries, func(i, j int) bool {
		return tries[i].PublieLe > tries[j].PublieLe
	})
	if max > 0 && len(tries) > max {
		tries = tries[:max]
	}
	tuiles := make([]TuileMosaique, 0, len(tries))
	for _, c := range tries {
		tuiles = append(tuiles, tuileDepuisContenu(c))
	}
	return tuiles
}
