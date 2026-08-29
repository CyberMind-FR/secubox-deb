// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"html"
	"net/url"
	"strconv"
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
	return objetMedia(id, "", []string{u},
		`<iframe class="sbx-embed sbx-embed-yt" src="https://www.youtube-nocookie.com/embed/`+
			html.EscapeString(id)+`" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen loading="lazy"></iframe>`), true
}

// embedMediaURL rend l'OBJET MÉDIA d'une URL vidéo, quelle que soit sa source.
// C'est le point d'entrée du rendu « en tête de fil » (objetMediaURL) : les fils
// passerelle portent aussi bien du YouTube (première vue, à rapatrier) que du
// PeerTube DÉJÀ SOUVERAIN (mirroir de la box). PUR : aucun réseau.
func embedMediaURL(u string) (string, bool) {
	if h, ok := embedYouTubeURL(u); ok {
		return h, true
	}
	if estPeertube(u) {
		return objetMediaPeertube(u), true
	}
	return "", false
}

// estPeertube reconnaît une URL de NOTRE instance PeerTube (visionnage ou embed).
// On ne borne pas l'hôte ici — le rendu ne fait qu'un <iframe> vers l'URL fournie,
// déjà écrite par la passerelle depuis nos propres répliques.
func estPeertube(u string) bool {
	return strings.Contains(u, "/videos/embed/") ||
		strings.Contains(u, "/videos/watch/") ||
		strings.Contains(u, "/w/")
}

// objetMediaPeertube enveloppe un lecteur PeerTube en objet média DÉJÀ SOUVERAIN
// (#1266b) : la vidéo vit sur l'instance de la box, il n'y a donc rien à
// rapatrier — pas de « ⤓ souverain ». Reste la barre : relayé (souverain), le
// VOIR en grand dans le Hall, le DIFFUSER au parc. La source « voir/diffuser »
// est l'URL PeerTube elle-même, que le lecteur du Hall sait cadrer.
func objetMediaPeertube(u string) string {
	embed := peertubeEmbedURL(u)
	src := html.EscapeString(embed)
	return `<figure class="sbx-mediaobj" data-pt="` + src + `">` +
		`<div class="sbx-mediaobj-vue"><iframe class="sbx-embed" src="` + src +
		`" allowfullscreen loading="lazy"></iframe></div>` +
		`<figcaption class="sbx-mediaobj-bar">` +
		`<span class="mo-id" title="Hébergé et relayé par la box — déjà souverain">🛰️ souverain</span>` +
		`<a class="mo-act mo-voir" href="` + src + `" data-voir title="Voir en grand dans le lecteur du Hall">▢ voir</a>` +
		`<a class="mo-act mo-diff" href="` + src + `" data-diff title="Diffuser au parc (📡 direct)">📡 diffuser</a>` +
		`</figcaption></figure>`
}

// compteSources dédoublonne origine + répliques pour dire la RICHESSE de l'objet
// (combien d'endroits connaissent ce média : l'original + ses miroirs/caches).
// Le join reste par video_id ailleurs ; ici on ne fait que compter des adresses.
func compteSources(sources []string, origine string) int {
	vu := map[string]bool{}
	ajoute := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			vu[s] = true
		}
	}
	ajoute(origine)
	for _, s := range sources {
		ajoute(s)
	}
	return len(vu)
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
func objetMedia(id, titre string, sources []string, lecteur string) string {
	watchBrut := "https://www.youtube.com/watch?v=" + id // non-échappé : pour les URL
	watch := html.EscapeString(watchBrut)
	ytsas := "https://ytsas.gk2.secubox.in/?src=" + url.QueryEscape(watchBrut)
	t := html.EscapeString(titre)
	// Compte de sources : l'original + ses répliques (miroir/cache). >1 = l'objet
	// vit à plusieurs endroits ; on le dit, discrètement.
	src := ""
	if n := compteSources(sources, watchBrut); n > 1 {
		src = `<span class="mo-src" title="` + strconv.Itoa(n) + ` sources connues pour ce média">· ` + strconv.Itoa(n) + ` sources</span>`
	}
	return `<figure class="sbx-mediaobj" data-yt="` + html.EscapeString(id) + `">` +
		`<div class="sbx-mediaobj-vue">` + lecteur + `</div>` +
		`<figcaption class="sbx-mediaobj-bar">` +
		`<span class="mo-id" title="Relayé à travers la box — pisteurs coupés">🛰️ relayé</span>` + src +
		// ▢ voir : promotion dans le lecteur du Hall (souverain, re-résolu), instance unique.
		`<a class="mo-act mo-voir" href="` + watch + `" data-voir data-titre="` + t + `" title="Voir en grand dans le lecteur du Hall (souverain)">▢ voir</a>` +
		// ⤓ souverain : DÉCLENCHE le rapatriement (ytsas add+conserve) en tâche de
		// fond — l'objet, re-résolu aux vues suivantes, montrera de lui-même la
		// source souveraine (cache puis miroir PeerTube). `data-souverain` porte
		// l'URL source ; hors Hall (href), le lien ouvre ytsas comme repli.
		`<a class="mo-act mo-ytsas" href="` + ytsas + `" data-souverain="` + watch + `" title="Rapatrier sur la box — version souveraine (ytsas → PeerTube)">⤓ souverain</a>` +
		// 📡 diffuser (#1224) : le média vu devient un flux diffusé au parc.
		`<a class="mo-act mo-diff" href="` + watch + `" data-diff data-titre="` + t + `" title="Diffuser au parc (📡 direct)">📡 diffuser</a>` +
		`</figcaption></figure>`
}

// embedYouTube rend l'embed selon l'état du tuyau souverain — consommé par
// l'upgrade côté serveur (Task 8) quand ytsas a répondu. mirror → PeerTube
// (souverain) ; cache → <video> locale (souverain) ; sinon youtube-nocookie.
func embedYouTube(c gateway.Contenu) string {
	rawID := c.Metadonnees["video_id"]
	return objetMedia(rawID, c.Titre, sourcesDe(c), lecteurSelonEtat(c, html.EscapeString(rawID)))
}

// lecteurSelonEtat rend le LECTEUR nu selon l'état du tuyau souverain : mirror →
// PeerTube, cache → <video> ytsas, sinon youtube-nocookie (première vue). Séparé
// de l'enveloppe pour que l'objet média la porte de façon uniforme.
func lecteurSelonEtat(c gateway.Contenu, id string) string {
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

// sourcesDe rassemble le jeu de sources d'un contenu : l'original (failover,
// jamais jeté) + ses répliques (miroir PeerTube, archive…). Sert le compte de
// l'objet média — le join reste par video_id ailleurs.
func sourcesDe(c gateway.Contenu) []string {
	out := []string{c.SourceURL}
	for _, r := range c.Repliques {
		if r.CibleURL != "" {
			out = append(out, r.CibleURL)
		}
	}
	return out
}
