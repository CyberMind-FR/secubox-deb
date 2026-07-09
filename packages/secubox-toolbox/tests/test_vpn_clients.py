# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

CONF = Path(__file__).resolve().parents[1] / "conf"


def test_prerouting_chain_and_set_present():
    nft = (CONF / "nft-toolbox-tor.nft").read_text()
    assert "set tor_vpn_src" in nft
    # a prerouting nat chain that redirects listed sources to TransPort/DNSPort
    assert "prerouting" in nft and "9040" in nft and "9053" in nft
    assert "ip saddr @tor_vpn_src" in nft
