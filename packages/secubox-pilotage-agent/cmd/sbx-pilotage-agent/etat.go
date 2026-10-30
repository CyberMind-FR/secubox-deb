// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/etat"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

// cheminEtat : page d'état locale (L5 tâche 7), dans le RuntimeDirectory de l'unité (secubox/pilotage).
const cheminEtat = "/run/secubox/pilotage/etat.html"

// cheminsEtat : les seuls chemins lus pour la page (mémoire, services, mains liées).
var cheminsEtat = []string{"Device.DeviceInfo.MemoryStatus.", "Device.X_SECUBOX_Services.", "Device.X_SECUBOX_Pilotage.MainsLiees"}

// suiviMaitre : dernier état du maître vu par le canal (0 inconnu, 1 joignable, 2 injoignable).
type suiviMaitre struct{ v atomic.Int32 }

func (s *suiviMaitre) Noter(ok bool) {
	if ok {
		s.v.Store(1)
	} else {
		s.v.Store(2)
	}
}

func (s *suiviMaitre) Etat() string {
	switch s.v.Load() {
	case 1:
		return etat.MaitreJoignable
	case 2:
		return etat.MaitreInjoignable
	}
	return etat.MaitreInconnu
}

// lecteurEtat : l'état de la page, lu dans le modèle (jamais par le maître) à chaque tour.
func lecteurEtat(m *modele.Modele, s *suiviMaitre, nomMachine func() (string, error)) func(context.Context) etat.Etat {
	return func(ctx context.Context) etat.Etat {
		nom, _ := nomMachine()
		return etat.Depuis(etat.NomSur(nom), s.Etat(), modele.Aplatir(m.Get(ctx, cheminsEtat)), time.Now())
	}
}
