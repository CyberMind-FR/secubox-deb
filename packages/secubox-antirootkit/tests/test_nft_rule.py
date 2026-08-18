# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from pathlib import Path

def test_antiescape_rule():
    """Test that the nft anti-escape rule file has all required components."""
    txt = Path("nft/secubox-antiescape.nft").read_text()
    assert "sbx-untrusted.slice" in txt
    assert "cgroupv2" in txt
    assert "drop" in txt
    # LAN carve-out so a jailed proc can still reach the local mgmt net (no exfil, but debuggable)
    assert "192.168.0.0/16" in txt or "@lan_safe" in txt
    # Loopback carve-out to prevent breaking jailed process's local DNS/loopback services
    assert "127.0.0.0/8" in txt
    assert "hook output" in txt
