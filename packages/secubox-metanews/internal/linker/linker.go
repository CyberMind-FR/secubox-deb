// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package linker : les LINKERS de MetaNews — connecteurs BIDIRECTIONNELS vers
// le monde extérieur. Deux verbes, hérités des zanimalos Peek et Poke :
//
//	PEEK  (in  / lecture)  → []Contenu normalisés  (RSS, Atom, plus tard fédiverse)
//	POKE  (out / écriture) ← publier/répondre à la source (réservé ; RSS = lecture seule)
//
// RSS est un linker « à la Mastodon » : même patron, même objet normalisé. La
// couche est pensée pour absorber ensuite Mastodon/fédiverse/réseaux SaaS en
// lecture ET écriture, sans changer de forme.
package linker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// Contenu : l'objet NORMALISÉ produit par un Peek, quel que soit le connecteur.
type Contenu struct {
	Titre      string `json:"titre"`
	Corps      string `json:"corps"`
	URL        string `json:"url"`
	Ref        string `json:"ref"`     // guid/id stable — sert à l'idempotence
	Auteur     string `json:"auteur"`
	Langue     string `json:"langue"`
	PublieLe   int64  `json:"publie_le"`
	Connecteur string `json:"connecteur"` // "rss", "atom", "mastodon"…
}

// OutMsg : message à POUSSER vers une source (Poke). Réservé — non utilisé par
// le MVP RSS, mais fixé pour que Mastodon/fédiverse gagnent l'écriture plus tard.
type OutMsg struct {
	Texte   string
	EnLien  string // URL à citer, facultatif
	Reponse string // ref d'un message auquel répondre, facultatif
}

// Ref : identité d'un objet distant après un Poke.
type Ref struct {
	ID  string
	URL string
}

// Sante : état d'un linker.
type Sante struct {
	OK    bool   `json:"ok"`
	Note  string `json:"note"`
	Vus   int    `json:"vus"`
}

// ErrLectureSeule : un linker en lecture seule refuse Poke.
var ErrLectureSeule = errors.New("linker en lecture seule (pas de Poke)")

// Linker : le contrat bidirectionnel. Un connecteur en lecture seule renvoie
// ErrLectureSeule à Poke.
type Linker interface {
	ID() string
	Peek(depuis int64) ([]Contenu, error)
	Poke(msg OutMsg) (Ref, error)
	Sante() Sante
}

// Empreinte : hash stable du titre + résumé NORMALISÉS. Deux dépêches clonées
// (même contenu, sites différents) obtiennent la même empreinte → comptées
// comme UNE origine, pas N.
func Empreinte(titre, resume string) string {
	n := normaliser(titre + " " + resume)
	h := sha256.Sum256([]byte(n))
	return hex.EncodeToString(h[:16])
}

// normaliser : minuscules, espaces compactés, ponctuation légère retirée.
func normaliser(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	espace := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r >= 0x00C0 && r <= 0x024F:
			b.WriteRune(r)
			espace = false
		case r == ' ' || r == '\t' || r == '\n':
			if !espace {
				b.WriteByte(' ')
				espace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}
