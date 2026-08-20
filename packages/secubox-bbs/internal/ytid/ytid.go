// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package ytid extrait l'identifiant canonique (11 car.) d'une URL YouTube.
//
// PARTAGÉ entre internal/web (rendu de l'embed) et internal/connectors (le
// connecteur youtube, pour le backfill quand ytsas est HS) — auparavant
// dupliqué en local dans embed_youtube.go, avec le risque de diverger.
// Miroir Go de ytid.py côté ytsas : le join du tuyau souverain se fait par
// CET identifiant, jamais par le titre.
package ytid

import (
	"net/url"
	"regexp"
	"strings"
)

var reID = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)

// VideoID extrait l'identifiant canonique (11 car.) d'une URL YouTube, ou ""
// si ce n'en est pas une.
func VideoID(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	h := strings.TrimPrefix(strings.ToLower(p.Hostname()), "www.")
	switch h {
	case "youtube.com", "m.youtube.com":
		if p.Path == "/watch" {
			if v := p.Query().Get("v"); reID.MatchString(v) {
				return v
			}
			return ""
		}
		for _, pf := range []string{"/shorts/", "/embed/", "/v/"} {
			if strings.HasPrefix(p.Path, pf) {
				v := strings.SplitN(strings.TrimPrefix(p.Path, pf), "/", 2)[0]
				if reID.MatchString(v) {
					return v
				}
				return ""
			}
		}
		return ""
	case "youtu.be":
		// TrimLeft (pas TrimPrefix) : `youtu.be//ID` doit se comporter comme
		// le `lstrip("/")` de ytid.py côté ytsas et rendre quand même l'id.
		v := strings.SplitN(strings.TrimLeft(p.Path, "/"), "/", 2)[0]
		if reID.MatchString(v) {
			return v
		}
	}
	return ""
}
