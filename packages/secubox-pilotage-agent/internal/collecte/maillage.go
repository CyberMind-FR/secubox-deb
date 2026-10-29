// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"net"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
)

const racineMaillage = "Device.X_SECUBOX_Mesh."

// interfacesMaillage par ordre de préférence.
var interfacesMaillage = []string{"wg-mesh", "wg-autoload"}

type maillage struct {
	interfaces func() ([]net.Interface, error)
	adresses   func(net.Interface) ([]net.Addr, error)
}

// NouvelleSourceMaillage décrit l'interface WireGuard du maillage.
func NouvelleSourceMaillage(interfaces func() ([]net.Interface, error)) modele.Source {
	return nouvelleSourceMaillage(interfaces, func(i net.Interface) ([]net.Addr, error) { return i.Addrs() })
}

func nouvelleSourceMaillage(interfaces func() ([]net.Interface, error), adresses func(net.Interface) ([]net.Addr, error)) modele.Source {
	return &maillage{interfaces: interfaces, adresses: adresses}
}

func (s *maillage) Nom() string { return "maillage" }

func (s *maillage) Chemins() []string {
	return []string{racineMaillage + "Interface", racineMaillage + "Address", racineMaillage + "Present"}
}

func (s *maillage) Lire(ctx context.Context) (map[string]any, error) {
	ifs, err := s.interfaces()
	if err != nil {
		return nil, err
	}
	p := map[string]any{racineMaillage + "Present": false}
	for _, voulu := range interfacesMaillage {
		for _, i := range ifs {
			if i.Name != voulu {
				continue
			}
			p[racineMaillage+"Present"] = true
			p[racineMaillage+"Interface"] = i.Name
			if as, err := s.adresses(i); err == nil {
				for _, a := range as {
					if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
						p[racineMaillage+"Address"] = ipn.IP.String()
						break
					}
				}
			}
			return p, nil
		}
	}
	return p, nil
}
