// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

const racinePilotage = "Device.X_SECUBOX_Pilotage."

type pilotage struct{ racine, version string }

// NouvelleSourcePilotage publie la version de l'agent, l'état des mains liées
// et le profil actif.
func NouvelleSourcePilotage(racine string, version string) modele.Source {
	return &pilotage{racine: racine, version: version}
}

func (s *pilotage) Nom() string { return "pilotage" }

func (s *pilotage) Chemins() []string {
	return []string{racinePilotage + "AgentVersion", racinePilotage + "MainsLiees", racinePilotage + "Profil"}
}

func (s *pilotage) Lire(ctx context.Context) (map[string]any, error) {
	_, err := os.Stat(filepath.Join(s.racine, "etc/secubox/pilotage/mains-liees"))
	profil := ""
	if b, err := os.ReadFile(filepath.Join(s.racine, "var/lib/secubox/profiles/actif")); err == nil {
		profil = strings.TrimSpace(string(b))
	}
	return map[string]any{
		racinePilotage + "AgentVersion": s.version,
		racinePilotage + "MainsLiees":   err == nil,
		racinePilotage + "Profil":       profil,
	}, nil
}
