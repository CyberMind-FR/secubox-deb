// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

const racineExposition = "Device.X_SECUBOX_Exposure."

type exposition struct{ racine string }

// NouvelleSourceExposition publie les noms de vhosts nginx et les ports TCP en
// écoute (exigence E4), par lecture de fichiers seulement.
func NouvelleSourceExposition(racine string) modele.Source { return &exposition{racine: racine} }

func (s *exposition) Nom() string { return "exposition" }

func (s *exposition) Chemins() []string {
	return []string{racineExposition + "Names", racineExposition + "Ports"}
}

func (s *exposition) Lire(ctx context.Context) (map[string]any, error) {
	ports, err := s.ports()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		racineExposition + "Names": s.noms(),
		racineExposition + "Ports": ports,
	}, nil
}

// noms rend les server_name non génériques, triés et sans doublon. Un
// répertoire absent donne une liste vide.
func (s *exposition) noms() []string {
	fichiers, _ := filepath.Glob(filepath.Join(s.racine, "etc/nginx/sites-enabled/*"))
	vus := map[string]bool{}
	noms := []string{}
	for _, fich := range fichiers {
		f, err := os.Open(fich)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l, _, _ := strings.Cut(sc.Text(), "#")
			l = strings.TrimSpace(l)
			if !strings.HasPrefix(l, "server_name") {
				continue
			}
			l = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(l, "server_name")), ";")
			for _, n := range strings.Fields(l) {
				if n == "_" || n == "localhost" || strings.HasPrefix(n, "~") || vus[n] {
					continue
				}
				vus[n] = true
				noms = append(noms, n)
			}
		}
		f.Close()
	}
	sort.Strings(noms)
	return noms
}

// ports rend les ports TCP à l'écoute (état 0A), triés, de tcp et tcp6.
func (s *exposition) ports() ([]int, error) {
	vus := map[int]bool{}
	lu := false
	for _, nom := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		f, err := os.Open(filepath.Join(s.racine, nom))
		if err != nil {
			continue
		}
		lu = true
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			c := strings.Fields(sc.Text())
			if len(c) < 4 || c[3] != "0A" {
				continue
			}
			_, hex, ok := strings.Cut(c[1], ":")
			if !ok {
				continue
			}
			if v, err := strconv.ParseUint(hex, 16, 16); err == nil {
				vus[int(v)] = true
			}
		}
		f.Close()
	}
	if !lu {
		return nil, errors.New("/proc/net/tcp illisible")
	}
	ports := make([]int, 0, len(vus))
	for p := range vus {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}
