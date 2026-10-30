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
	"net"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/canal"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/operations"
)

// Vérification de l'ancre du maître (D1, #3126 L2) : la seule voie est le ctl
// root, par l'argv exact que le sudoers accorde. L'agent ne lit ni wg ni l'ancre.
const (
	cheminSudo = "/usr/bin/sudo"
	cheminCtl  = operations.CheminCtl
	delaiCtl   = 60 * time.Second
)

// interfaceAncre rend l'interface du canal du maître retenu (R-L2-23) : celle
// que le ctl doit vérifier. Vide pour un maître hors des deux canaux.
func interfaceAncre(maitre string) string {
	hote := maitre
	if h, _, err := net.SplitHostPort(maitre); err == nil {
		hote = h
	}
	switch hote {
	case "10.10.0.1":
		return "wg-mesh"
	case "10.64.0.1":
		return "wg-autoload"
	}
	return ""
}

// verifieurAncre rend la vérification passée au canal, pour l'interface du
// canal de maitre (jamais deviné d'après les interfaces présentes : I1). AncreOK seulement si le
// ctl a écrit exactement un objet JSON {"ok": true} ; {"ok": false} reprend sa
// « raison » (absente, differente, illisible ; R-L2-19). Erreur, code non nul,
// sortie illisible, en trop ou incohérente : AncreIllisible (fermé par défaut).
func verifieurAncre(lancer func(ctx context.Context, args ...string) ([]byte, error), maitre string) func(ctx context.Context) canal.Verdict {
	iface := interfaceAncre(maitre)
	return func(ctx context.Context) canal.Verdict {
		if iface == "" {
			// Maître hors de wg-mesh et wg-autoload (127.0.0.1 des essais) : aucune ancre ne le couvre.
			log.Printf("ancre : maître %q hors des canaux du maillage, non vérifiable", maitre)
			return canal.AncreIllisible
		}
		b, err := lancer(ctx, "-n", cheminCtl, "ancre-verifier", iface)
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
