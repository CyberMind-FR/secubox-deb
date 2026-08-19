// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"html"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/ytid"
)

// embedYouTubeURL rend l'embed « première vue » (youtube-nocookie) d'une URL
// YouTube. PUR : appelé depuis le rendu du corps, sans réseau.
//
// referrerpolicy=strict-origin-when-cross-origin est OBLIGATOIRE ici : la page
// pose l'en-tête `Referrer-Policy: same-origin`, qui coupe le référent vers un
// tiers — le lecteur youtube-nocookie n'a alors plus l'origine dont il a besoin
// et affiche « Erreur 153 / Erreur de configuration du lecteur vidéo ».
// L'attribut de l'iframe SURCHARGE l'en-tête de page pour cette requête : on
// envoie l'ORIGINE seule (https://bbs…), jamais l'URL du fil ; avec -nocookie,
// c'est le bon compromis vie privée.
func embedYouTubeURL(u string) (string, bool) {
	id := ytid.VideoID(u)
	if id == "" {
		return "", false
	}
	return `<iframe class="sbx-embed sbx-embed-yt" src="https://www.youtube-nocookie.com/embed/` +
		html.EscapeString(id) + `" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen loading="lazy"></iframe>`, true
}

// embedYouTube rend l'embed selon l'état du tuyau souverain — consommé par
// l'upgrade côté serveur (Task 8) quand ytsas a répondu. mirror → PeerTube
// (souverain) ; cache → <video> locale (souverain) ; sinon youtube-nocookie.
func embedYouTube(c gateway.Contenu) string {
	id := html.EscapeString(c.Metadonnees["video_id"])
	switch c.Metadonnees["etat"] {
	case "mirror":
		for _, r := range c.Repliques {
			if r.Cible == "peertube" && r.CibleURL != "" {
				return `<iframe class="sbx-embed" src="` + html.EscapeString(r.CibleURL) +
					`" allowfullscreen loading="lazy"></iframe>`
			}
		}
		fallthrough // miroir annoncé mais URL absente : on retombe sur WAN
	case "cache":
		if s := c.Metadonnees["stream_url"]; s != "" {
			return `<video class="sbx-embed" controls preload="metadata" src="` + html.EscapeString(s) + `"></video>`
		}
		fallthrough
	default: // pending / inconnu → WAN (première vue)
		return `<iframe class="sbx-embed" src="https://www.youtube-nocookie.com/embed/` + id +
			`" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen loading="lazy"></iframe>`
	}
}
