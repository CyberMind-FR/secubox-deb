// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
)

// ActionPilotageAdmin : action de `politique` du ctl qui dit si la portée admin du pilotage HTTP (L5) est permise
// maintenant : mains libres ET (box du propriétaire OU box cliente pendant un support ouvert), ancre vérifiée.
const ActionPilotageAdmin = "pilotage-admin"

// PolitiqueAdmin interroge le ctl root (la politique est décidée par lui, sur son état root) ; admin seulement sur
// un {"autorise": true} net ; toute erreur ou sortie inattendue vaut lecture (fermé par défaut).
func PolitiqueAdmin(ctl Lanceur) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		b, err := ctl(ctx, "-n", CheminCtl, "politique", ActionPilotageAdmin)
		if err != nil {
			log.Printf("politique %s : ctl en échec (%v), portée lecture", ActionPilotageAdmin, err)
			return false
		}
		var r struct {
			Autorise *bool `json:"autorise"`
		}
		dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(b)))
		if dec.Decode(&r) != nil || dec.More() || r.Autorise == nil {
			log.Printf("politique %s : réponse du ctl illisible, portée lecture", ActionPilotageAdmin)
			return false
		}
		return *r.Autorise
	}
}
