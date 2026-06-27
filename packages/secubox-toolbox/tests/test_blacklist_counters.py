# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Every named counter referenced in the blacklist spine is declared (ref #758)."""
import re
from pathlib import Path

NFT = Path(__file__).resolve().parents[1] / "nftables.d" / "secubox-blacklist.nft"
EXPECTED = {
    "sbx_drop_blacklist_v4", "sbx_drop_blacklist_v6",
    "sbx_drop_quarantine_v4", "sbx_drop_quarantine_v6",
    "sbx_doh_detect_v4", "sbx_doh_detect_v6",
}


def _decls_and_refs(text):
    decls = set(re.findall(r'counter\s+([a-z0-9_]+)\s*\{', text))
    refs = set(re.findall(r'counter name "([a-z0-9_]+)"', text))
    return decls, refs


def test_named_counters_declared_and_referenced():
    text = NFT.read_text()
    decls, refs = _decls_and_refs(text)
    assert EXPECTED <= refs, f"missing refs: {EXPECTED - refs}"
    assert refs <= decls, f"undeclared counters referenced: {refs - decls}"
