// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"fmt"
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
// l'emporte pour l'adresse du maître ; l'adresse de sortie (IPSource, forme
// CIDR) est celle de l'interface du maillage dont la plage contient le maître
// (les paquets sortis d'un autre tunnel seraient jetés). Sans correspondance
// (loopback, interface absente), elle reste vide : le noyau choisit.
// trouve est faux quand il n'y a ni maître explicite ni interface utilisable.
func choisirMaitre(explicite string, ifs []ifaceAdr) (maitre, ipSource string, trouve bool) {
	explicite = strings.TrimSpace(explicite)
	if explicite != "" {
		hote := explicite
		if h, _, err := net.SplitHostPort(explicite); err == nil {
			hote = h
		}
		ip, err := netip.ParseAddr(strings.Trim(hote, "[]"))
		if err != nil {
			return explicite, "", true
		}
		for _, c := range canauxMaitre {
			if c.plage.Contains(ip) {
				return explicite, adresseDe(c.iface, c.plage, ifs), true
			}
		}
		return explicite, "", true
	}
	for _, c := range canauxMaitre {
		if a := adresseDe(c.iface, c.plage, ifs); a != "" {
			return c.maitre, a, true
		}
	}
	return "", "", false
}

// adresseDe rend l'adresse (CIDR) de l'interface qui tombe dans la plage.
func adresseDe(iface string, plage netip.Prefix, ifs []ifaceAdr) string {
	for _, i := range ifs {
		if i.Nom != iface {
			continue
		}
		for _, a := range i.Adresses {
			if a.Addr().Is4() && plage.Contains(a.Addr()) {
				return a.String()
			}
		}
	}
	return ""
}

// maitresAdmis : seuls ces maîtres sont joignables (IPAddressAllow de l'unité).
// Pas de nom d'hôte : aucune résolution DNS sous le profil AppArmor.
var maitresAdmis = []netip.Addr{
	netip.MustParseAddr("10.10.0.1"), netip.MustParseAddr("10.64.0.1"),
	netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"),
}

// validerMaitre contrôle PILOTAGE_MAITRE : vide (découverte) ou « IP[:port] »
// avec une IP littérale admise et un port de 1 à 65535.
func validerMaitre(m string) error {
	m = strings.TrimSpace(m)
	if m == "" {
		return nil
	}
	hote := m
	if h, p, err := net.SplitHostPort(m); err == nil {
		hote = h
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("port %q invalide", p)
		}
	}
	ip, err := netip.ParseAddr(strings.Trim(hote, "[]"))
	if err != nil {
		return fmt.Errorf("%q : adresse IP littérale attendue (pas de nom d'hôte)", m)
	}
	for _, ok := range maitresAdmis {
		if ip == ok {
			return nil
		}
	}
	return fmt.Errorf("%q : maître non admis (10.10.0.1, 10.64.0.1 ou loopback)", m)
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
	intervalleMax    = 300 * time.Second
)

// intervalleReleve lit PILOTAGE_RELEVE_INTERVALLE_S : 30 s par défaut, jamais
// sous 5 s ni au-dessus de 300 s (le détecteur ne doit pas saturer la box).
func intervalleReleve(env string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(env))
	if err != nil || n <= 0 {
		return intervalleDefaut
	}
	if n >= int(intervalleMax/time.Second) {
		return intervalleMax
	}
	if d := time.Duration(n) * time.Second; d > intervalleMin {
		return d
	}
	return intervalleMin
}

// estLeMaitre : la box porte elle-même l'adresse du maître sur l'interface du
// tunnel retenue (gk2 : wg-mesh en 10.10.0.1). En L1 le maître ne se pilote pas
// par son propre canal (R35) : le canal refuse .1 (identite._hote) et chaque
// essai écrirait une ligne d'audit.
func estLeMaitre(maitre, ipSource string) bool {
	if ipSource == "" {
		return false
	}
	src, err := netip.ParsePrefix(ipSource)
	if err != nil {
		return false
	}
	hote := maitre
	if h, _, err := net.SplitHostPort(maitre); err == nil {
		hote = h
	}
	ip, err := netip.ParseAddr(strings.Trim(hote, "[]"))
	return err == nil && ip == src.Addr()
}
