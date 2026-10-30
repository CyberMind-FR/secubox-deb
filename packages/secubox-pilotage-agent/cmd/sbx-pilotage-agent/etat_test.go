// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/etat"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

type sourceEtat struct{}

func (sourceEtat) Nom() string { return "etat" }
func (sourceEtat) Lire(context.Context) (map[string]any, error) {
	return map[string]any{"Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available": uint64(400 * 1024),
		"Device.X_SECUBOX_Pilotage.MainsLiees": true}, nil
}
func (sourceEtat) Chemins() []string {
	return []string{"Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available", "Device.X_SECUBOX_Pilotage.MainsLiees"}
}

// La page d'état se construit sans maître : état « inconnu » tant que le canal n'a fait aucun tour.
func TestEtatLocalSansMaitreDansLAgent(t *testing.T) {
	var suivi suiviMaitre
	lire := lecteurEtat(modele.NouveauModele(sourceEtat{}), &suivi, func() (string, error) { return "gk5.lan", nil })
	e := lire(context.Background())
	if e.Nom != "gk5" || e.Maitre != etat.MaitreInconnu || !e.MainsLiees || e.MemDispoMo != 400 {
		t.Errorf("état = %+v", e)
	}
	suivi.Noter(true)
	if lire(context.Background()).Maitre != etat.MaitreJoignable {
		t.Errorf("joignable non vu")
	}
	suivi.Noter(false)
	if lire(context.Background()).Maitre != etat.MaitreInjoignable {
		t.Errorf("injoignable non vu")
	}
}
