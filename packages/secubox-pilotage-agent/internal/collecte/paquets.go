// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"bufio"
	"context"
	"fmt"
	"os"
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
	f, err := os.Open(filepath.Join(s.racine, "var/lib/dpkg/status"))
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
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		l := sc.Text()
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
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	clore()
	return p, nil
}
