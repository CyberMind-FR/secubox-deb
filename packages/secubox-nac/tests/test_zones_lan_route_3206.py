# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3206 — netmodes accepte en entrée le LAN du mode routeur (br-lan) comme le réseau de la Freebox. « IoT isolé » et
« Invités » doivent le rester : depuis br-lan, vers la box, DNS et DHCP seulement (la chaîne du NAC, à filter - 5, passe
avant ; un drop y est final). Hors br-lan, rien ne change."""
import pathlib

from api import zones_info

NFT = (pathlib.Path(__file__).resolve().parents[1] / "nft" / "secubox-nac.nft").read_text(encoding="utf-8")


def _entree():
    debut = NFT.index("chain input {")
    return [l.strip() for l in NFT[debut:NFT.index("\n\t}", debut)].splitlines() if l.strip() and not l.strip().startswith("#")]


def test_iot_et_invites_sur_br_lan_n_ont_que_dns_et_dhcp_vers_la_box():
    regles = _entree()
    for zone in ("iot_zone", "guest_zone"):
        r = [l for l in regles if f"@{zone}" in l]
        assert f'iifname "br-lan" ether saddr @{zone} udp dport {{ 53, 67 }} return' in r, zone
        assert f'iifname "br-lan" ether saddr @{zone} tcp dport 53 return' in r, zone
        drop = [l for l in r if l.startswith(f'iifname "br-lan" ether saddr @{zone} counter drop')]
        assert len(drop) == 1, zone
        assert r.index(drop[0]) > r.index(f'iifname "br-lan" ether saddr @{zone} tcp dport 53 return')


def test_hors_br_lan_rien_ne_change():
    for l in _entree():
        if "@iot_zone" in l or "@guest_zone" in l:
            assert l.startswith('iifname "br-lan"'), l


def test_description_dit_la_regle():
    for nom in ("iot", "guest"):
        assert any("br-lan" in r and "DNS" in r for r in zones_info.ZONES_COMPORTEMENT[nom]["regles"]), nom


def test_reponses_aux_connexions_de_la_box_avant_les_refus():
    """Revue #3206 : sans cela, l'écho ICMP d'un appareil IoT au ping de dnsmasq (avant bail) était refusé."""
    regles = _entree()
    ret = 'iifname "br-lan" ct state established,related return'
    i = next(i for i, l in enumerate(regles) if l.startswith(ret))
    premiers_drops = [i2 for i2, l in enumerate(regles) if l.startswith('iifname "br-lan" ether saddr @') and "drop" in l]
    assert premiers_drops and i < min(premiers_drops)
