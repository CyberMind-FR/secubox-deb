// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/lecture"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

var nomProfil = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

const (
	racinePilotage = "Device.X_SECUBOX_Pilotage."
	// drapeauMainsLiees : sous /etc/secubox, dont le compte partagé secubox est propriétaire (R12, R36).
	drapeauMainsLiees = "etc/secubox/pilotage/mains-liees"
)

type pilotage struct {
	racine, version string
	proprio         lecture.Proprietaire // propriétaire exigé du drapeau (root:root)

	mu         sync.Mutex
	dernierRef string // dernier refus journalisé : une ligne par refus nouveau, pas une par lecture
}

// NouvelleSourcePilotage publie la version de l'agent, l'état des mains liées
// et le profil actif.
func NouvelleSourcePilotage(racine string, version string) modele.Source {
	return &pilotage{racine: racine, version: version, proprio: lecture.Root}
}

func (s *pilotage) Nom() string { return "pilotage" }

func (s *pilotage) Chemins() []string {
	return []string{racinePilotage + "AgentVersion", racinePilotage + "MainsLiees", racinePilotage + "Profil"}
}

func (s *pilotage) Lire(ctx context.Context) (map[string]any, error) {
	liees := s.mainsLiees()
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
		racinePilotage + "MainsLiees":   liees,
		racinePilotage + "Profil":       profil,
	}, nil
}

// mainsLiees : le drapeau n'est cru que s'il est root:root, sans droit
// d'écriture groupe/autres, sans lien ni dans son chemin ni en lui-même (lu par
// descripteur). Un drapeau non fiable vaut « non » et donne une ligne de
// journal à chaque refus nouveau, pas à chaque lecture.
func (s *pilotage) mainsLiees() bool {
	err := lecture.PresentDeConfiance(s.racine, drapeauMainsLiees, s.proprio)
	refus := ""
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		refus = err.Error()
	}
	s.mu.Lock()
	nouveau := refus != "" && refus != s.dernierRef
	s.dernierRef = refus
	s.mu.Unlock()
	if nouveau {
		log.Printf("drapeau mains liées ignoré : %s (attendu : fichier régulier root:root, sans droit d'écriture groupe/autres)", refus)
	}
	return err == nil
}
