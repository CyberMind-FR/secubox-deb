# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 5b (#3374) : la couverture « DNS + DPI » ne compte que des flux vers un TIERS. Une TV dont gk2 ne voit que le DNS qu'elle lui
envoie (conntrack voit ce DNS, port 53 ou 853 de la box) reste « DNS seulement » (défaut relevé par le propriétaire)."""
from api import dnstv_dpi as D

MAC = "aa:bb:cc:00:00:01"
TV = "192.168.1.50"
BOX = {"192.168.1.1", "2a01:e0a::1"}


def _ct(src, dst, dport, proto="udp"):
    num = "17" if proto == "udp" else "6"
    return (f"ipv4     2 {proto}      {num} 29 src={src} dst={dst} sport=40000 dport={dport} src={dst} dst={src} sport={dport} "
            f"dport=40000 mark=0 use=1\n")


class SansDNS:
    def evenements(self, clients, depuis, limite=20000):
        return []


def _passage(tmp_path, texte, now=1_800_000_000):
    etat = {"actif": True, "clients": [{"ip": TV, "nom": "TV", "mode": "auto", "mac": MAC}]}
    m = D.MagasinDPI(tmp_path / "d.db")
    r = D.passage(etat, SansDNS(), m, lambda d: "INCONNU", now, {}, None, texte, set(), BOX, (set(), set()))
    return r["etat"]["appareils"][0]["couverture"], m


def test_dns_vers_la_box_seulement_reste_dns_seulement(tmp_path):
    texte = _ct(TV, "192.168.1.1", 53) + _ct(TV, "192.168.1.1", 853, "tcp")
    couverture, m = _passage(tmp_path, texte)
    assert couverture == "dns"
    assert m.dernier_flux(MAC) is None                     # aucun flux vers la box n'est rangé


def test_flux_vers_un_tiers_compte_comme_dpi(tmp_path):
    texte = _ct(TV, "192.168.1.1", 53) + _ct(TV, "151.101.1.9", 443, "tcp")
    couverture, m = _passage(tmp_path, texte)
    assert couverture == "dns+dpi"
    assert [x["distant"] for x in m.lignes_flux(MAC, 0)[1]] == ["151.101.1.9"]


def test_flux_tiers_pur():
    flux = [{"distant": "192.168.1.1", "port": 53}, {"distant": "2a01:e0a::1", "port": 443}, {"distant": "9.9.9.9", "port": 53},
            {"distant": "", "port": 443}]
    assert D.flux_tiers(flux, BOX) == [{"distant": "9.9.9.9", "port": 53}, {"distant": "", "port": 443}]
