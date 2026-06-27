# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: secubox-hub network-stats (#758).

Shared by the root collector (write path: collect_once/main) and the FastAPI
app (read path: read_snapshot/query_series). Pure functions are unit-tested;
the privileged collect path is integration-tested with monkeypatched sources.
"""
from __future__ import annotations
import json
import sqlite3
import subprocess
import time
from pathlib import Path

DB_PATH = Path("/var/lib/secubox/hub/netstats.db")
SNAP_PATH = Path("/var/lib/secubox/hub/netstats.json")
DATA_DIR = DB_PATH.parent
STALE_AFTER_S = 120  # snapshot older than this is flagged stale

# counter-name → category. Named counters live in the owning packages' tables.
CATEGORY_MAP = {
    "sbx_drop_blacklist_v4": "blacklist", "sbx_drop_blacklist_v6": "blacklist",
    "sbx_drop_quarantine_v4": "quarantine", "sbx_drop_quarantine_v6": "quarantine",
    "sbx_doh_detect_v4": "doh", "sbx_doh_detect_v6": "doh",
    "sbx_drop_wafrl": "waf_ratelimit",
    "sbx_drop_input_policy": "input_policy",
}
# Categories that count toward "network_drops" (doh is detect-only, excluded).
DROP_CATEGORIES = {"blacklist", "quarantine", "waf_ratelimit", "input_policy", "crowdsec"}


def category_for(name: str) -> str | None:
    return CATEGORY_MAP.get(name)


def parse_proc_net_dev(text: str) -> dict[str, dict]:
    """Parse /proc/net/dev → {iface: {rx_bytes,rx_packets,tx_bytes,tx_packets}}.
    Skips the two header lines and the loopback interface.
    """
    out: dict[str, dict] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if name == "lo" or not name:
            continue
        f = rest.split()
        if len(f) < 16:
            continue
        out[name] = {
            "rx_bytes": int(f[0]), "rx_packets": int(f[1]),
            "tx_bytes": int(f[8]), "tx_packets": int(f[9]),
        }
    return out


def parse_nft_counters_json(data: dict) -> dict[str, dict]:
    """Parse `nft -j list counters` (or list table) → {name: {packets,bytes}}."""
    out: dict[str, dict] = {}
    for item in data.get("nftables", []):
        c = item.get("counter")
        if isinstance(c, dict) and "name" in c:
            out[c["name"]] = {
                "packets": int(c.get("packets", 0) or 0),
                "bytes": int(c.get("bytes", 0) or 0),
            }
    return out


def reset_aware_delta(prev: int, cur: int) -> int:
    """Monotonic-counter delta that tolerates resets (nft reload → cur < prev)."""
    if cur < prev:
        return cur
    return cur - prev
