// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"errors"
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
	ports, err := s.ports(ctx)
	if err != nil {
		return nil, err
	}
	noms, err := s.noms(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		racineExposition + "Names": noms,
		racineExposition + "Ports": ports,
	}, nil
}

// noms rend les server_name non génériques, triés et sans doublon. Un
// répertoire absent donne une liste vide.
func (s *exposition) noms(ctx context.Context) ([]string, error) {
	fichiers, _ := filepath.Glob(filepath.Join(s.racine, "etc/nginx/sites-enabled/*"))
	if len(fichiers) > maxFichiersVhs {
		fichiers = fichiers[:maxFichiersVhs]
	}
	vus := map[string]bool{}
	noms := []string{}
	for _, fich := range fichiers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, err := ouvrirBorne(fich, plafondVhost)
		if err != nil {
			continue
		}
		err = parcourirLignes(ctx, f, func(l string) {
			l, _, _ = strings.Cut(l, "#")
			champs := strings.Fields(strings.TrimSuffix(strings.TrimSpace(l), ";"))
			if len(champs) < 2 || champs[0] != "server_name" {
				return
			}
			for _, n := range champs[1:] {
				if n == "_" || n == "localhost" || strings.HasPrefix(n, "~") || vus[n] {
					continue
				}
				vus[n] = true
				noms = append(noms, n)
			}
		})
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(noms)
	return noms, nil
}

// ports rend les ports TCP à l'écoute (état 0A), triés, de tcp et tcp6.
func (s *exposition) ports(ctx context.Context) ([]int, error) {
	vus := map[int]bool{}
	lu := false
	for _, nom := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		f, err := ouvrirBorne(filepath.Join(s.racine, nom), plafondReseau)
		if err != nil {
			continue
		}
		lu = true
		err = parcourirLignes(ctx, f, func(l string) {
			c := strings.Fields(l)
			if len(c) < 4 || c[3] != "0A" {
				return
			}
			if _, hex, ok := strings.Cut(c[1], ":"); ok {
				if v, err := strconv.ParseUint(hex, 16, 16); err == nil {
					vus[int(v)] = true
				}
			}
		})
		f.Close()
		if err != nil {
			return nil, err
		}
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
