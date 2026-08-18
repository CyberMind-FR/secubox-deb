# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def test_nft_redirects_only_automap_range_to_transport():
    n = (ROOT / "nft.d/secubox-tor-transparent.nft").read_text()
    assert "table inet secubox-tor-transparent" in n
    assert "10.192.0.0/10" in n
    assert "9040" in n
    # portée : wg-toolbox + LAN, hook prerouting dstnat
    assert "wg-toolbox" in n
    assert "type nat hook prerouting" in n
