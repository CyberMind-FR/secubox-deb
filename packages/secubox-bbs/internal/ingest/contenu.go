// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Pont Item → gateway.Contenu (#1049).
//
// Les collecteurs produisent des Item ; la passerelle (et la mosaïque) parlent
// gateway.Contenu. Ce pont convertit l'un en l'autre pour peupler
// gateway_contenu, ce que GatewayRecents relit ensuite pour la mosaïque. La
// vignette devient un média IMAGE, que la tuile relaie localement (jamais l'hôte
// tiers, #1056).
package ingest

import (
	"path"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// genreDepuisKind traduit le « kind » du collecteur en genre de la passerelle.
func genreDepuisKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "video":
		return gateway.GenreVideo
	case "audio":
		return gateway.GenreAudio
	case "image":
		return gateway.GenreImage
	case "texte", "text", "":
		return gateway.GenreTexte
	default:
		return gateway.GenreMixte
	}
}

// mimeImageDepuisURL devine le mime d'un poster depuis son extension. Le relais
// (media_relais.go) n'accepte que des images ; par défaut on suppose du JPEG,
// le cas PeerTube/podcaster le plus courant.
func mimeImageDepuisURL(u string) string {
	ext := strings.ToLower(path.Ext(strings.SplitN(u, "?", 2)[0]))
	switch ext {
	case ".png":
		return "image/png"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	case ".avif":
		return "image/avif"
	default:
		return "image/jpeg"
	}
}

// ContenuDepuisItem convertit un Item de collecteur en gateway.Contenu prêt à
// être enregistré (GatewayEnregistrer). `propriete` doit valoir gateway.ProprieteSoi
// (contenu de la boîte, republiable) ou gateway.ProprieteTiers (agrégé).
func ContenuDepuisItem(it Item, connecteur, noeud, propriete string) gateway.Contenu {
	c := gateway.Contenu{
		Genre:        genreDepuisKind(it.Kind),
		Titre:        it.Titre,
		Corps:        it.Corps,
		SourceURL:    it.Lien,
		Connecteur:   connecteur,
		RefNative:    it.Ref,
		PublieLe:     it.Date,
		Propriete:    propriete,
		NoeudOrigine: noeud,
		Retention:    gateway.RetentionCache,
	}
	if it.Vignette != "" {
		c.Medias = append(c.Medias, gateway.Media{
			Chemin: it.Vignette,
			Mime:   mimeImageDepuisURL(it.Vignette),
		})
	}
	c.Empreinte = gateway.Empreinte(c)
	return c
}
