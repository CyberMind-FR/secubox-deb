# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: autolearn signals (Anti-Track v2 Plan 2a, #633)

Pure functions over a sqlite3 connection — no file/network I/O. Consumed by
sbin/secubox-toolbox-autolearn. Two signals:
  • cookie_xsite_trackers : cross-site pre-consent cookie setters (top-N capped)
  • pure_trackers         : hard-block allowlist (curated seed + auto-promote)
"""
from __future__ import annotations

import json
import sqlite3
from typing import Iterable

from secubox_toolbox.privacy import registrable


def cookie_xsite_trackers(conn: sqlite3.Connection, top_n: int = 5) -> list[str]:
    """Registrable tracker domains that set a cookie id reused across >=2 sites
    with at least one pre-consent observation, ranked by distinct clients then
    event count, truncated to top_n. Returns [] on any query error."""
    try:
        candidates = set()
        for r in conn.execute(
            "SELECT tracker_domain "
            "FROM social_edges "
            "WHERE cookie_id_hash IS NOT NULL AND cookie_id_hash <> '' "
            "GROUP BY cookie_id_hash, tracker_domain "
            "HAVING COUNT(DISTINCT src_site) >= 2 "
            "   AND SUM(CASE WHEN consent_state='pre_consent' THEN 1 ELSE 0 END) > 0"
        ):
            d = registrable(r["tracker_domain"])
            if d:
                candidates.add(d)
        if not candidates:
            return []
        agg: dict[str, list[int]] = {}  # reg -> [clients, hits]
        for r in conn.execute(
            "SELECT tracker_domain, COUNT(*) AS hits, "
            "       COUNT(DISTINCT client_mac_hash) AS clients "
            "FROM social_edges GROUP BY tracker_domain"
        ):
            d = registrable(r["tracker_domain"])
            if not d or d not in candidates:
                continue
            cur = agg.setdefault(d, [0, 0])
            cur[0] += int(r["clients"])
            cur[1] += int(r["hits"])
        ranked = sorted(agg.items(), key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))
        return [d for d, _ in ranked[:max(0, top_n)]]
    except sqlite3.Error:
        return []
