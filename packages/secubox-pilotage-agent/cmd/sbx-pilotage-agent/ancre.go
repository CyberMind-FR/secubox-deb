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

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/canal"
)

// Vérification de l'ancre du maître (D1, #3126 L2) : la seule voie est le ctl
// root, par l'argv exact que le sudoers accorde. L'agent ne lit ni wg ni l'ancre.
const (
	cheminSudo = "/usr/bin/sudo"
	cheminCtl  = "/usr/sbin/secubox-pilotagectl"
	delaiCtl   = 60 * time.Second
)

// verifieurAncre rend la vérification passée au canal. AncreOK seulement si le
// ctl a écrit exactement un objet JSON {"ok": true} ; {"ok": false} reprend sa
// « raison » (absente, differente, illisible ; R-L2-19). Erreur, code non nul,
// sortie illisible, en trop ou incohérente : AncreIllisible (fermé par défaut).
func verifieurAncre(lancer func(ctx context.Context, args ...string) ([]byte, error)) func(ctx context.Context) canal.Verdict {
	return func(ctx context.Context) canal.Verdict {
		b, err := lancer(ctx, "-n", cheminCtl, "ancre-verifier")
		if err != nil {
			log.Printf("ancre : vérification impossible (%v)", err)
			return canal.AncreIllisible
		}
		var r map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(b), &r); err != nil {
			log.Print("ancre : réponse du ctl illisible")
			return canal.AncreIllisible
		}
		_, avecRaison := r["raison"]
		if string(r["ok"]) == "true" && !avecRaison {
			return canal.AncreOK
		}
		var raison string
		if string(r["ok"]) == "false" && json.Unmarshal(r["raison"], &raison) == nil {
			switch v := canal.Verdict(raison); v {
			case canal.AncreAbsente, canal.AncreDifferente, canal.AncreIllisible:
				log.Printf("ancre : %s", v)
				return v
			}
		}
		log.Print("ancre : réponse du ctl incohérente")
		return canal.AncreIllisible
	}
}
