// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ifaceAdr : une interface réseau et ses adresses (forme CIDR).
type ifaceAdr struct {
	Nom      string
	Adresses []netip.Prefix
}

// Canaux du maillage, par ordre de préférence : interface, plage du tunnel, maître.
var canauxMaitre = []struct {
	iface  string
	plage  netip.Prefix
	maitre string
}{
	{"wg-mesh", netip.MustParsePrefix("10.10.0.0/24"), "10.10.0.1:8472"},
	{"wg-autoload", netip.MustParsePrefix("10.64.0.0/16"), "10.64.0.1:8472"},
}

// choisirMaitre applique la règle de découverte. PILOTAGE_MAITRE (explicite)
// l'emporte pour l'adresse du maître ; l'adresse de sortie (IPSource, forme CIDR)
// vient de la première interface du maillage qui porte une adresse dans sa plage.
// trouve est faux quand il n'y a ni maître explicite ni interface utilisable.
func choisirMaitre(explicite string, ifs []ifaceAdr) (maitre, ipSource string, trouve bool) {
	explicite = strings.TrimSpace(explicite)
	for _, c := range canauxMaitre {
		for _, i := range ifs {
			if i.Nom != c.iface {
				continue
			}
			for _, a := range i.Adresses {
				if a.Addr().Is4() && c.plage.Contains(a.Addr()) {
					if explicite != "" {
						return explicite, a.String(), true
					}
					return c.maitre, a.String(), true
				}
			}
		}
	}
	if explicite != "" {
		return explicite, "", true
	}
	return "", "", false
}

// lireInterfaces relève les interfaces de la box et leurs adresses.
func lireInterfaces() []ifaceAdr {
	ls, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var res []ifaceAdr
	for _, i := range ls {
		r := ifaceAdr{Nom: i.Name}
		if as, err := i.Addrs(); err == nil {
			for _, a := range as {
				if ipn, ok := a.(*net.IPNet); ok {
					if p, ok := netip.AddrFromSlice(ipn.IP); ok {
						ones, _ := ipn.Mask.Size()
						r.Adresses = append(r.Adresses, netip.PrefixFrom(p.Unmap(), ones))
					}
				}
			}
		}
		res = append(res, r)
	}
	return res
}

const (
	intervalleDefaut = 30 * time.Second
	intervalleMin    = 5 * time.Second
)

// intervalleReleve lit PILOTAGE_RELEVE_INTERVALLE_S : 30 s par défaut, jamais
// sous 5 s (le détecteur ne doit pas saturer la box).
func intervalleReleve(env string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(env))
	if err != nil || n <= 0 {
		return intervalleDefaut
	}
	if d := time.Duration(n) * time.Second; d > intervalleMin {
		return d
	}
	return intervalleMin
}
