// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"html"
	"net/url"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/ytid"
)

// peertubeEmbedURL derive l'URL D'INTEGRATION d'une URL PeerTube de visionnage.
//
// PeerTube protege ses pages `/w/{id}` et `/videos/watch/{id}` du cadrage
// (`X-Frame-Options`) — les encadrer donne « Firefox ne peut pas ouvrir cette
// page ». Seule `/videos/embed/{id}` est concue pour l'iframe. On garde l'URL de
// visionnage comme lien canonique et on n'en derive l'embed qu'au rendu (#1131b).
// Toute autre forme passe telle quelle : le repli reste sur.
func peertubeEmbedURL(u string) string {
	if i := strings.Index(u, "/videos/watch/"); i >= 0 {
		return u[:i] + "/videos/embed/" + u[i+len("/videos/watch/"):]
	}
	if i := strings.Index(u, "/w/"); i >= 0 {
		return u[:i] + "/videos/embed/" + u[i+len("/w/"):]
	}
	return u
}

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
	return objetMedia(id,
		`<iframe class="sbx-embed sbx-embed-yt" src="https://www.youtube-nocookie.com/embed/`+
			html.EscapeString(id)+`" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen loading="lazy"></iframe>`), true
}

// objetMedia enveloppe un lecteur embarque en OBJET MEDIA (#1227). Un lien nu
// n'etait qu'un lecteur ; l'objet porte son identite (relaye par la box, la
// matrice SBXOS) et sa barre d'ESCALADE : le voir (ephemere, deja la), le
// GARDER souverain (ytsas — cache/miroir), et — a venir — le DIFFUSER au parc
// (#1224). C'est la premiere pierre du meta-objet : il se materialise a
// l'affichage, et gagnera plus tard de reecrire son propre message pour
// historiser son evolution.
//
// Le lien « souverain » pointe l'origine ytsas de la box avec la video en
// parametre : embarque, la coquille BBS le route vers le Hall (sbx:ouvre-hote)
// qui l'ouvre en place ; autonome, c'est un lien direct vers un service de la
// box. On ne quitte jamais la matrice.
func objetMedia(id, lecteur string) string {
	watch := "https://www.youtube.com/watch?v=" + html.EscapeString(id)
	ytsas := "https://ytsas.gk2.secubox.in/?src=" + url.QueryEscape(watch)
	return `<figure class="sbx-mediaobj" data-yt="` + html.EscapeString(id) + `">` +
		`<div class="sbx-mediaobj-vue">` + lecteur + `</div>` +
		`<figcaption class="sbx-mediaobj-bar">` +
		`<span class="mo-id" title="Relayé à travers la box — pisteurs coupés">🛰️ relayé par la box</span>` +
		`<a class="mo-act mo-ytsas" href="` + ytsas + `" title="Garder sur la box — version souveraine (ytsas)">⤓ souverain</a>` +
		`<span class="mo-act mo-diff" title="Diffuser au parc — à venir (#1224)" aria-disabled="true">📡 diffuser</span>` +
		`</figcaption></figure>`
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
				return `<iframe class="sbx-embed" src="` + html.EscapeString(peertubeEmbedURL(r.CibleURL)) +
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
