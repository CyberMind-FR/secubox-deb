// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package linker : connecteurs SOCIAUX (Peek/Poke), même patron que MetaNews.
// Trois modes d'accès, JAMAIS de scraping (contourner un accès viole le principe
// SecuBox « ne jamais contourner les limitations d'accès ») :
//
//	open    — contenu public via API/flux ouverts (Mastodon, Bluesky, PeerTube, YouTube)
//	consent — API officielle avec un JETON fourni par l'opérateur (Facebook Graph)
//	bridge  — un flux (RSS/JSON) produit par un PONT que l'opérateur héberge lui-même
package linker

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Media : une pièce jointe d'un post.
type Media struct {
	URL  string `json:"url"`  // URL d'origine (sera CACHÉE localement, jamais servie au client)
	Kind string `json:"kind"` // image | video | gifv
	Desc string `json:"desc"`
}

// Contenu : un post NORMALISÉ, quel que soit le réseau.
type Contenu struct {
	Auteur   string  `json:"auteur"`
	URL      string  `json:"url"`
	Ref      string  `json:"ref"`
	Texte    string  `json:"texte"`
	PublieLe int64   `json:"publie_le"`
	Medias   []Media `json:"medias"`
	Reseau   string  `json:"reseau"` // mastodon | facebook | bridge
}

// EmpreinteURL : hash court d'une URL de média — sert de nom de fichier caché.
func EmpreinteURL(u string) string {
	h := sha256.Sum256([]byte(u))
	return hex.EncodeToString(h[:16])
}

// nettoyerHTML retire les balises grossières d'un contenu HTML (Mastodon rend
// du HTML) et compacte les espaces — on garde le TEXTE, pas la mise en forme.
func nettoyerHTML(s string) string {
	s = strings.ReplaceAll(s, "</p>", "\n\n")
	s = strings.ReplaceAll(s, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")
	s = strings.ReplaceAll(s, "<br />", "\n")
	var b strings.Builder
	dans := false
	for _, r := range s {
		switch r {
		case '<':
			dans = true
		case '>':
			dans = false
		default:
			if !dans {
				b.WriteRune(r)
			}
		}
	}
	// dé-échapper quelques entités courantes
	out := b.String()
	for _, kv := range [][2]string{{"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&#39;", "'"}, {"&quot;", "\""}, {"&nbsp;", " "}} {
		out = strings.ReplaceAll(out, kv[0], kv[1])
	}
	// compacter les lignes vides multiples
	for strings.Contains(out, "\n\n\n") {
		out = strings.ReplaceAll(out, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(out)
}
