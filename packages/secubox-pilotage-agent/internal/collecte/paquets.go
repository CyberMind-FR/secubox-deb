// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"fmt"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/lecture"
	"path/filepath"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

const (
	racinePaquets  = "Device.X_SECUBOX_Packages."
	maxPaquets     = 500
	paquetVersions = "secubox-core"
)

type paquets struct{ racine string }

// NouvelleSourcePaquets lit /var/lib/dpkg/status sous racine (vide en production).
func NouvelleSourcePaquets(racine string) modele.Source { return &paquets{racine: racine} }

func (s *paquets) Nom() string { return "paquets" }

func (s *paquets) Chemins() []string {
	return []string{
		racineDevice + "SoftwareVersion",
		racinePaquets + "{i}.Name",
		racinePaquets + "{i}.Version",
	}
}

func (s *paquets) Lire(ctx context.Context) (map[string]any, error) {
	f, err := lecture.Ouvrir(filepath.Join(s.racine, "var/lib/dpkg/status"), plafondDpkg)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p := map[string]any{}
	n := 0
	var nom, version, etat string
	clore := func() {
		if strings.HasPrefix(nom, "secubox-") && etat == "install ok installed" && n < maxPaquets {
			n++
			p[fmt.Sprintf("%s%d.Name", racinePaquets, n)] = nom
			p[fmt.Sprintf("%s%d.Version", racinePaquets, n)] = version
			if nom == paquetVersions {
				p[racineDevice+"SoftwareVersion"] = version
			}
		}
		nom, version, etat = "", "", ""
	}
	err = lecture.Lignes(ctx, f, func(l string) {
		switch {
		case l == "":
			clore()
		case strings.HasPrefix(l, "Package: "):
			nom = strings.TrimSpace(l[len("Package: "):])
		case strings.HasPrefix(l, "Version: "):
			version = strings.TrimSpace(l[len("Version: "):])
		case strings.HasPrefix(l, "Status: "):
			etat = strings.TrimSpace(l[len("Status: "):])
		}
	})
	if err != nil {
		return nil, err
	}
	// Fichier coupé par le plafond : la strophe finale est incomplète, on ne la publie pas.
	if !f.Tronque() {
		clore()
	}
	return p, nil
}
