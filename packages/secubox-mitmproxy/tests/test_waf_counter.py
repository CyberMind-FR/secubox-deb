# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""WAF rate-limit drops carry a named counter (ref #758)."""
import re
from pathlib import Path

NFT = Path(__file__).resolve().parents[1] / "nftables" / "secubox-waf-ratelimit.nft"


def test_wafrl_counter_declared_and_referenced():
    text = NFT.read_text()
    decls = set(re.findall(r'counter\s+([a-z0-9_]+)\s*\{', text))
    refs = set(re.findall(r'counter name "([a-z0-9_]+)"', text))
    assert "sbx_drop_wafrl" in refs
    assert "sbx_drop_wafrl" in decls
