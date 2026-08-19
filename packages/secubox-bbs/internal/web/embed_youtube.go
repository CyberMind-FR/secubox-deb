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
// YouTube. PUR : appelé depuis le rendu du corps, sans réseau. referrerpolicy
// no-referrer : le fil interne n'a pas à être annoncé au tiers.
func embedYouTubeURL(u string) (string, bool) {
	id := ytid.VideoID(u)
	if id == "" {
		return "", false
	}
	return `<iframe class="sbx-embed sbx-embed-yt" src="https://www.youtube-nocookie.com/embed/` +
		html.EscapeString(id) + `" allowfullscreen loading="lazy" referrerpolicy="no-referrer"></iframe>`, true
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
			`" allowfullscreen loading="lazy" referrerpolicy="no-referrer"></iframe>`
	}
}
