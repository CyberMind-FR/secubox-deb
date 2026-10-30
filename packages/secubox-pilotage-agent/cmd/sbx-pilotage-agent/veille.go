// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"log"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/operations"
)

// pasVeille : intervalle de lecture de l'état local (mains liées, consentements, support), 5 min (R-L2-30 : une ligne
// sudo par lecture dans auth.log, gk2 à 91 % de disque), plus une lecture juste après chaque Operate traité. Le verbe
// `etat` n'est pas audité ; seules les expirations qu'il constate le sont. Une bascule locale arrive donc au maître en
// 5 min au plus ; la fin d'une session de support, elle, est portée par sa notification d'ouverture (`fin`).
const pasVeille = 5 * time.Minute

// veiller lit l'état local au ctl (`sudo -n secubox-pilotagectl etat` : aucun droit en plus du sudoers existant, et
// rien que l'agent puisse modifier) et pousse X_SECUBOX_HandsTied, X_SECUBOX_Consent et X_SECUBOX_Support quand il
// change. La lecture déclenche aussi, côté ctl, les expirations (consentement à 24 h, fin du support). Une lecture
// en échec ne produit rien (journalisée une fois par erreur nouvelle) ; une notification qui ne trouve pas de place
// dans la file est perdue et journalisée (le maître relit l'état par Get).
// relire (peut être nil) : une lecture immédiate est demandée (après un Operate, voir apresOperate).
func veiller(ctx context.Context, ctl operations.Lanceur, pas time.Duration, relire <-chan struct{}, ev chan<- notifs.Evenement) {
	b := notifs.NouvellesBascules(nil)
	derniere := ""
	t := time.NewTicker(pas)
	defer t.Stop()
	for {
		sortie, err := ctl(ctx, "-n", operations.CheminCtl, "etat")
		var e notifs.EtatLocal
		if err == nil {
			e, err = operations.LireEtat(sortie)
		}
		switch {
		case err != nil && ctx.Err() == nil:
			if err.Error() != derniere {
				log.Printf("état local illisible (%v) : bascules non notifiées tant qu'il le reste", err)
			}
			derniere = err.Error()
		case err == nil:
			derniere = ""
			for _, n := range b.Observer(e) {
				select {
				case ev <- n:
				default:
					log.Printf("notification %s abandonnée (file pleine)", n.Type)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-relire:
		}
	}
}

// apresOperate enveloppe le traitement des Operate d'action : une fois la réponse obtenue, il demande à la veille une
// lecture immédiate de l'état (un consentement créé, un support demandé ou fermé se voient aussitôt). Le signal ne
// bloque jamais ; plusieurs Operate rapprochés donnent une seule lecture.
func apresOperate(agir func(context.Context, string, map[string]any, string) operations.Reponse, relire chan<- struct{}) func(context.Context, string, map[string]any, string) operations.Reponse {
	return func(ctx context.Context, cmd string, args map[string]any, acteur string) operations.Reponse {
		r := agir(ctx, cmd, args, acteur)
		select {
		case relire <- struct{}{}:
		default:
		}
		return r
	}
}
