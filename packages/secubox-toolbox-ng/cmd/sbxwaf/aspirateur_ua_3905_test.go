// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"testing"
	"time"
)

const uaAspirateur3905 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

// #3905 : l'aspirateur distribué de Gitea (UA figé, 1 000+ adresses) est banni dès sa 1re requête, 7 jours.
func TestAspirateurUABanni3905(t *testing.T) {
	r := LoadRules(corpusLivre)
	cat, _, mode, hit := r.MatchModes("GET", "/gandalf/secubox-deb/src/commit/d59ce53152e921324d295db78301095a373d95b1/packages", "", "", uaAspirateur3905, true)
	if !hit || cat != "aspirateur_ua" || mode != "escalate" {
		t.Fatalf("aspirateur non bloqué : cat=%q mode=%q hit=%v", cat, mode, hit)
	}
	if seuil, duree := r.ParamsBan("aspirateur_ua"); seuil != 1 || duree != 24*time.Hour {
		t.Fatalf("ban attendu 1re requête, 24 h : seuil=%d durée=%s", seuil, duree)
	}
}

// Les navigateurs voisins ne sont pas touchés : autre version, autre système, ou UA prolongé.
func TestAspirateurUAVoisinsLibres3905(t *testing.T) {
	r := LoadRules(corpusLivre)
	for _, ua := range []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
		uaAspirateur3905 + " Edg/150.0.0.0",
	} {
		if cat, _, _, hit := r.MatchModes("GET", "/", "", "", ua, true); hit && cat == "aspirateur_ua" {
			t.Fatalf("UA voisin pris pour l'aspirateur : %s", ua)
		}
	}
}
