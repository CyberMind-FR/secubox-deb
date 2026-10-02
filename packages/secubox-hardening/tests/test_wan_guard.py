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
