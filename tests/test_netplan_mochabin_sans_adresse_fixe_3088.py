# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3088 — le netplan commun des MOCHAbin ne donne aucune adresse fixe à eth2.

Banc 2026-10-24 : une MOCHAbin fraîchement flashée a pris 192.168.1.200, l'adresse de gk2, sur le même réseau
(arping : deux MAC pour .200, « martian source … from 192.168.1.200 »). gk2 tient .200 de son bail DHCP."""
from pathlib import Path

import yaml

NETPLAN = Path(__file__).resolve().parents[1] / "board" / "mochabin" / "netplan" / "00-secubox.yaml"


def test_eth2_en_dhcp_sans_adresse_ni_route_fixe():
    eth2 = yaml.safe_load(NETPLAN.read_text())["network"]["ethernets"]["eth2"]
    assert eth2["dhcp4"] is True
    assert "addresses" not in eth2
    assert "routes" not in eth2
    assert "192.168.1.200" not in NETPLAN.read_text()
