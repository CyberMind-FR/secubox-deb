# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Pure parsers for the network-stats collector (ref #758)."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
netstats = importlib.import_module("netstats")

PROC = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "    lo:  123 4 0 0 0 0 0 0  123 4 0 0 0 0 0 0\n"
    "  eth0: 1000 10 0 0 0 0 0 0  2000 20 0 0 0 0 0 0\n"
)


def test_parse_proc_net_dev_skips_lo_header():
    out = netstats.parse_proc_net_dev(PROC)
    assert "lo" not in out
    assert out["eth0"] == {"rx_bytes": 1000, "rx_packets": 10, "tx_bytes": 2000, "tx_packets": 20}


def test_parse_nft_counters_json():
    data = {"nftables": [
        {"counter": {"name": "sbx_drop_blacklist_v4", "packets": 5, "bytes": 500}},
        {"counter": {"name": "irrelevant", "packets": 9, "bytes": 9}},
        {"rule": {"chain": "x"}},
    ]}
    out = netstats.parse_nft_counters_json(data)
    assert out["sbx_drop_blacklist_v4"] == {"packets": 5, "bytes": 500}
    assert "irrelevant" in out  # parser keeps all; mapping happens via category_for


def test_category_for():
    assert netstats.category_for("sbx_drop_blacklist_v6") == "blacklist"
    assert netstats.category_for("sbx_drop_quarantine_v4") == "quarantine"
    assert netstats.category_for("sbx_drop_wafrl") == "waf_ratelimit"
    assert netstats.category_for("sbx_drop_input_policy") == "input_policy"
    assert netstats.category_for("sbx_doh_detect_v4") == "doh"
    assert netstats.category_for("nope") is None


def test_reset_aware_delta():
    assert netstats.reset_aware_delta(100, 150) == 50      # normal
    assert netstats.reset_aware_delta(150, 10) == 10       # reset → treat cur as delta
    assert netstats.reset_aware_delta(0, 0) == 0
