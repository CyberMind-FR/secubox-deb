// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/operations"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/releve"
)

const commandeMesurer = "Device.X_SECUBOX_Releve.Mesurer()"

// sortieProc et sortieReleve : forme JSON du relevé (snake_case), la même pour
// tous les champs ; releve.Releve ne porte pas de balises.
type sortieProc struct {
	Nom    string  `json:"nom"`
	CPUPct float64 `json:"cpu_pct"`
	PSSMo  int     `json:"pss_mo"`
}

type sortieReleve struct {
	DureeS       int          `json:"duree_s"`
	CPUPct       int          `json:"cpu_pct"`
	CtxtParS     int64        `json:"ctxt_par_s"`
	EcrituresKoS int64        `json:"ecritures_ko_s"`
	MemDispoMo   int          `json:"mem_dispo_mo"`
	SwapMo       int          `json:"swap_mo"`
	Top          []sortieProc `json:"top"`
}

// attendreReel attend d ou l'annulation de ctx : un relevé de 300 s s'arrête
// dès SIGTERM.
func attendreReel(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// operateur relie l'OPERATE du canal à releve.Mesurer. attendre nil = attente réelle.
func operateur(racine string, attendre func(context.Context, time.Duration) error) func(ctx context.Context, cmd string, args map[string]any) (any, error) {
	if attendre == nil {
		attendre = attendreReel
	}
	return func(ctx context.Context, cmd string, args map[string]any) (any, error) {
		if cmd != commandeMesurer {
			return nil, errors.New("commande refusée (L1 : lecture seule)")
		}
		duree := 60
		switch v := args["duree_s"].(type) {
		case int:
			duree = v
		case float64:
			duree = int(v)
		}
		r, err := releve.Mesurer(ctx, racine, time.Duration(duree)*time.Second, attendre)
		if err != nil {
			return nil, err
		}
		s := sortieReleve{r.DureeS, r.CPUPct, r.CtxtParS, r.EcrituresKoS, r.MemDispoMo, r.SwapMo, make([]sortieProc, 0, len(r.Top))}
		for _, p := range r.Top {
			s.Top = append(s.Top, sortieProc{p.Nom, p.CPUPct, p.PSSMo})
		}
		return s, nil
	}
}

// operateurBox est l'opérateur de production : relevé lu sous la racine absolue « / » (M2), comme le modèle ; jamais
// des chemins relatifs, qui ne marcheraient que parce que systemd place le répertoire courant à « / ».
func operateurBox(attendre func(context.Context, time.Duration) error) func(ctx context.Context, cmd string, args map[string]any) (any, error) {
	return operateur("/", attendre)
}

// executeur relie les Operate d'action (L2) au ctl root : ctl lance `sudo -n /usr/sbin/secubox-pilotagectl …`
// (ctlEntree de même, avec une entrée standard : le code de Rejoindre, R-L2-2),
// systemctl lit l'état de l'unité de l'opération sans sudo. La progression part dans la file des notifications sans
// jamais bloquer (perdue si la file est pleine) ; les fins vont dans la boîte des résultats (au plus 50, renvoyés
// à la reconnexion).
func executeur(ctl operations.Lanceur, ctlEntree operations.LanceurEntree, systemctl operations.Lanceur, ev chan<- notifs.Evenement) (*operations.Executeur, *operations.Boite) {
	boite := operations.NouvelleBoite(operations.MaxResultats)
	return operations.Nouveau(operations.Config{
		Ctl:       ctl,
		CtlEntree: ctlEntree,
		Systemctl: systemctl,
		Resultats: boite,
		Progression: func(e notifs.Evenement) {
			select {
			case ev <- e:
			default:
				log.Printf("progression de %s abandonnée (file pleine)", e.Job)
			}
		},
	}), boite
}
