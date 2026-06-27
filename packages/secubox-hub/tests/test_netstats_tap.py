# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""The hub input policy-drop tap declares + references its counter (ref #758)."""
import re
from pathlib import Path

NFT = Path(__file__).resolve().parents[1] / "nftables.d" / "zz-secubox-netstats-tap.nft"


def test_tap_counter_present_and_zz_ordered():
    assert NFT.name.startswith("zz-"), "tap must sort after accept rules"
    text = NFT.read_text()
    assert re.search(r'counter\s+sbx_drop_input_policy\s*\{', text)
    assert re.search(r'add rule inet filter input .*counter name "sbx_drop_input_policy"', text)
    # additive only — must NOT delete or flush the base filter table
    assert "delete table inet filter" not in text
    assert "flush ruleset" not in text
