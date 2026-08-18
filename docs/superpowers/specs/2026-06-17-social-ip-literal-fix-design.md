<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# social-graph — drop IP-literal tracker edges + KPI consistency (#642)

- **Date:** 2026-06-17 · **Package:** `secubox-toolbox` · **Issue:** #642
- **Status:** Design approved, pending plan

## Problem
`#social` KPI `total_trackers_seen` counts IP-literal hosts (the client's own
no-SNI traffic to gk2 service IPs — health pings, loader fetches) while the
`by_tracker_domain` table filters them via `_is_ip()` → KPI and table disagree
("4" vs "aucun"), and `social_edges` fills with IP-literal noise.

## Fix (two points in `secubox_toolbox/social.py`)
1. **Source — `_record_edge_sync`:** early-return when `_is_ip(tracker_domain)`
   (the single chokepoint both `social_graph.py` call sites pass through). No
   IP-literal "tracker" is ever recorded. `_is_ip` (defined at :700) resolves at
   call-time, so the forward reference from the earlier `_record_edge_sync` is fine.
2. **KPI — `aggregate`:** replace the raw
   `total_trackers_seen = SELECT COUNT(DISTINCT tracker_domain)` with
   `total_trackers_seen = len(_byd)` computed AFTER the existing `_byd` fold
   (distinct non-IP registrable domains). KPI then matches the table and is robust
   to legacy IP rows already in the DB.

## Decisions
- Scope: IP-literals only (matches the observed noise + the issue's wording).
  Skipping gk2's own *hostname* vhosts (kbin/admin/peertube.gk2.secubox.in) is a
  separate, larger allowlist concern — out of scope.
- `total_trackers_seen` semantic becomes "distinct non-IP registrable trackers" =
  the table's universe (table shows top-50 of it). Consistent.

## Tests (`tests/test_social_edges.py`, in-memory sqlite, monkeypatch `social.DB_PATH`)
- `_record_edge_sync`: IP-literal tracker_domain (`1.2.3.4`, `2001:db8::1`) → no
  row; a hostname (`www.criteo.com`) → row inserted.
- `aggregate`: seed edges with 2 hostname trackers + 1 IP-literal → already-present
  IP row is excluded → `total_trackers_seen == len(by_tracker_domain) == 2`.

## Error handling / rollout
`_record_edge_sync` keeps its best-effort try/except. No schema change; legacy
IP rows age out (7-day edge retention) and are already excluded from both metrics
after the fix. Cosmetic + noise reduction; no enforcement/engine impact. Deploy =
portal restart (aggregate) + mitm-wg workers reload (record_edge addon).

## Out of scope
- Hostname-based gk2 self-traffic allowlist; backfilling/deleting existing IP rows
  (they expire via retention).
