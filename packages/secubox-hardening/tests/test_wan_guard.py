# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Garde des ports de backend (#1306) : lecture de la règle livrée et des écoutes."""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "wan_guard", Path(__file__).parent.parent / "api" / "wan_guard.py")
wg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wg)

LIVREE = Path(__file__).parent.parent / "nft" / "secubox-wan-guard.nft"


def test_regle_livree_lue():
    iface, ports = wg.ports_gardes(LIVREE.read_text())
    assert iface == "eth2"
    assert {8088, 8900, 9080, 8910} <= set(ports)
    assert {23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017} <= set(ports)   # leurres
    assert 445 not in ports                       # vrai SMB, cantonné par secubox-smb
    assert not set(ports) & wg.FRONTAUX          # jamais couper SSH / HAProxy


def test_commentaires_ignores():
    assert wg.ports_gardes('# iifname "eth2" tcp dport { 1 } drop') == ("", [])


def test_ecoutes_hors_boucle_locale():
    ss = ("LISTEN 0 511 0.0.0.0:8088 0.0.0.0:*\n"
          "LISTEN 0 511 127.0.0.1:8085 0.0.0.0:*\n"
          "LISTEN 0 511 [::]:9080 [::]:*\n"
          "LISTEN 0 511 [::1]:3000 [::]:*\n")
    assert wg.ports_en_ecoute(ss) == {8088: "0.0.0.0", 9080: "::"}


def test_tunnels_non_signales():
    assert wg.joignable_depuis_lan("0.0.0.0") and wg.joignable_depuis_lan("192.168.1.200")
    assert not wg.joignable_depuis_lan("10.99.1.1") and not wg.joignable_depuis_lan("192.168.255.1")


BASE = Path(__file__).parent.parent / "nft" / "nftables.conf"


def test_base_geree_sans_interface_en_dur():
    texte = BASE.read_text()
    assert "SecuBox-managed: secubox-hardening" in texte     # marqueur de la postinst
    assert "table inet filter" in texte                      # les fragments nftables.d y ajoutent des règles
    assert "policy drop" in texte
    # Aucune interface de confiance en dur : elles viennent de nft-input-trust.d.
    assert not [l for l in texte.splitlines() if l.strip().startswith('iif "')]
    assert 'nft-site.d' in texte                              # NAT propre à la box
    for port in ('51820', '51822', '8799', 'udp dport 68', 'ipv6-icmp'):   # héritage firstboot / gk3
        assert port in texte
    assert "nft-input-trust.d" in texte
    assert 'include "/etc/nftables.d/*.nft"' in texte


def test_jonction_du_maillage_ouverte_au_lan_fermee_a_internet():
    # #3103 : eth2 de gk2 porte le WAN ET le LAN (réseau de la Freebox). 7331 dans la liste coupée rendait toute
    # jonction au maillage impossible depuis le LAN (gk1 : curl 000, sbx-mesh-join en échec).
    texte = LIVREE.read_text()
    _, ports = wg.ports_gardes(texte)
    assert 7331 not in ports
    regles = [l.strip() for l in texte.splitlines() if "7331" in l and not l.lstrip().startswith("#")]
    v4 = [l for l in regles if "ip saddr !=" in l]
    assert v4, "7331 doit rester coupé sur eth2 pour les adresses non privées"
    for reseau in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert reseau in v4[0]
    assert "drop" in v4[0]
    assert any("nfproto ipv6" in l and "drop" in l for l in regles)     # jamais en IPv6 depuis eth2


def test_lan_route_meme_garde_que_eth2():
    """#3206 : netmodes accepte br-lan en entrée comme eth2 ; sans la même garde, l'admin nginx :9080 (sans HAProxy ni
    sbxwaf), les statistiques HAProxy :8404 et les leurres seraient joignables depuis le LAN du mode routeur."""
    import re
    texte = LIVREE.read_text()
    listes = {}
    for ligne in texte.splitlines():
        m = re.search(r'iifname "(\w[\w-]*)" tcp dport \{ ([\d, ]+) \} counter drop', ligne)
        if m and not ligne.lstrip().startswith("#"):
            listes[m.group(1)] = sorted(int(p) for p in m.group(2).split(","))
    assert set(listes) == {"eth2", "br-lan"}
    assert listes["br-lan"] == listes["eth2"]                      # une seule liste, jamais deux qui divergent
    assert 9080 in listes["br-lan"] and 8404 in listes["br-lan"]
    assert re.search(r'iifname "br-lan" meta nfproto ipv6 tcp dport 7331 counter drop', texte)
