// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"time"
)

// Vérification de l'ancre du maître (D1, #3126 L2) : la seule voie est le ctl
// root, par l'argv exact que le sudoers accorde. L'agent ne lit ni wg ni l'ancre.
const (
	cheminSudo = "/usr/bin/sudo"
	cheminCtl  = "/usr/sbin/secubox-pilotagectl"
	delaiCtl   = 60 * time.Second
)

// verifieurAncre rend la vérification passée au canal : vrai seulement si le
// ctl a écrit exactement un objet JSON dont « ok » vaut true. Erreur, code non
// nul, sortie illisible ou en trop : faux (fermé par défaut).
func verifieurAncre(lancer func(ctx context.Context, args ...string) ([]byte, error)) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		b, err := lancer(ctx, "-n", cheminCtl, "ancre-verifier")
		if err != nil {
			log.Printf("ancre : vérification impossible (%v)", err)
			return false
		}
		var r map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(b), &r); err != nil {
			log.Print("ancre : réponse du ctl illisible")
			return false
		}
		if string(r["ok"]) == "true" {
			return true
		}
		var refus string
		if json.Unmarshal(r["refus"], &refus) != nil || len(refus) > 64 {
			refus = "?"
		}
		log.Printf("ancre : refusée par le ctl (%s)", refus)
		return false
	}
}
