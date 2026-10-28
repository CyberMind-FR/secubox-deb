// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/lecture"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

var nomProfil = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

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
	// Lecture bornée à 128 octets ; une valeur qui n'est pas un nom de profil
	// valide n'est pas publiée.
	if b, err := lecture.Lire(filepath.Join(s.racine, "var/lib/secubox/profiles/actif"), 128); err == nil {
		if v := strings.TrimSpace(string(b)); nomProfil.MatchString(v) {
			profil = v
		}
	}
	return map[string]any{
		racinePilotage + "AgentVersion": s.version,
		racinePilotage + "MainsLiees":   err == nil,
		racinePilotage + "Profil":       profil,
	}, nil
}
