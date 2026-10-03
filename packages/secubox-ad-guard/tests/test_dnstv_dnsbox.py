# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Fiche « DNS de la box » (#1938) : adresses du LAN, laquelle est stable, et si Unbound écoute dessus. Sorties réelles relevées sur gk2."""
from api import dnstv_dnsbox as B

IP6 = """4: eth2    inet6 2a01:e0a:dec:c4e0:f2ad:4eff:fe27:889b/64 scope global dynamic mngtmpaddr noprefixroute \\       valid_lft 85915sec preferred_lft 85915sec
4: eth2    inet6 2a01:e0a:dec:c4e0::200/64 scope global \\       valid_lft forever preferred_lft forever
"""
IP4 = """1: lo    inet 192.168.255.1/24 brd 192.168.255.255 scope global lo\\       valid_lft forever preferred_lft forever
4: eth2    inet 192.168.1.200/24 metric 100 brd 192.168.1.255 scope global dynamic eth2\\       valid_lft 33159sec preferred_lft 33159sec
10: br-lxc    inet 10.100.0.1/24 brd 10.100.0.255 scope global br-lxc\\       valid_lft forever preferred_lft forever
"""
ROUTE = "default via 192.168.1.254 dev eth2 proto dhcp src 192.168.1.200 metric 100\n"
SS = """UNCONN 0      0                                    10.100.0.1:53    0.0.0.0:*
UNCONN 0      0                                192.168.1.200:53    0.0.0.0:*
UNCONN 0      0      [2a01:e0a:dec:c4e0:f2ad:4eff:fe27:889b]:53          *:*
UNCONN 0      0                     [2a01:e0a:dec:c4e0::200]:53          *:*
UNCONN 0      0                                        [::1]:53          *:*
UNCONN 0      0                                    127.0.0.1:53    0.0.0.0:*
"""


def par_adresse(fiche):
    return {a["adresse"]: a for a in fiche["adresses"]}


def test_releve_reel_de_gk2():
    f = B.dns_box(IP6, IP4, ROUTE, SS)
    assert f["interface"] == "eth2"
    a = par_adresse(f)
    assert set(a) == {"192.168.1.200", "2a01:e0a:dec:c4e0::200", "2a01:e0a:dec:c4e0:f2ad:4eff:fe27:889b"}     # seulement l'interface du LAN
    assert a["2a01:e0a:dec:c4e0::200"]["type"] == "stable" and a["2a01:e0a:dec:c4e0::200"]["ecoute"] is True
    assert a["2a01:e0a:dec:c4e0:f2ad:4eff:fe27:889b"]["type"] == "slaac"
    assert a["192.168.1.200"]["type"] == "ipv4" and a["192.168.1.200"]["ecoute"] is True
    assert f["alertes"] == []


def test_adresse_presente_mais_non_ecoutee_donne_une_alerte():
    """Le cas vécu le 2026-10-03 : ::200 posée sur eth2 mais Unbound ne l'écoutait pas encore."""
    ss = "\n".join(ligne for ligne in SS.splitlines() if "::200" not in ligne)
    f = B.dns_box(IP6, IP4, ROUTE, ss)
    assert par_adresse(f)["2a01:e0a:dec:c4e0::200"]["ecoute"] is False
    assert any("n'écoute pas" in x and "2a01:e0a:dec:c4e0::200" in x for x in f["alertes"])


def test_sans_ipv6_stable_alerte_et_slaac_deconseillee():
    ip6 = IP6.splitlines()[0] + "\n"
    f = B.dns_box(ip6, IP4, ROUTE, SS)
    assert any("aucune ipv6 stable" in x.lower() for x in f["alertes"])


def test_adresse_temporaire_reconnue():
    ip6 = "4: eth2    inet6 2a01:e0a:dec:c4e0:1:2:3:4/64 scope global temporary dynamic \\       valid_lft 600sec preferred_lft 100sec\n"
    assert par_adresse(B.dns_box(ip6, IP4, ROUTE, SS))["2a01:e0a:dec:c4e0:1:2:3:4"]["type"] == "temporaire"


def test_sorties_vides_ou_illisibles_ne_levent_rien():
    f = B.dns_box("", "", "", "")
    assert f["adresses"] == [] and f["interface"] is None and f["alertes"]
    f = B.dns_box("n'importe quoi", "###", "default via", "UNCONN truc")
    assert f["adresses"] == []


def test_suffixe_d_interface_et_ligne_sans_port_ignores():
    ss = "UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\nUNCONN 0 0 192.168.1.200:5353 0.0.0.0:*\nUNCONN 0 0 192.168.1.200:53 0.0.0.0:*\n"
    assert par_adresse(B.dns_box("", IP4, ROUTE, ss))["192.168.1.200"]["ecoute"] is True
    ss2 = "UNCONN 0 0 192.168.1.200:5353 0.0.0.0:*\n"                           # port 5353 (mDNS) ≠ DNS
    assert par_adresse(B.dns_box("", IP4, ROUTE, ss2))["192.168.1.200"]["ecoute"] is False
