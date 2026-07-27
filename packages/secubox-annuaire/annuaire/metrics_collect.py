# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: metrics_collect
Local snapshot collection for fleet metrics (MetricSnapshot fields, minus sig).

PURE-ish: the only side effects are the three pluggable readers (cache file,
systemctl, journal). Each is called through an injectable parameter so tests
run against fakes — never real systemctl/cache/journal state. The `_default_*`
readers are the production path.

collect_snapshot() NEVER raises: every reader call is individually guarded,
and any missing/malformed reader output degrades to safe zero values rather
than stopping a publish cycle. A single flaky metrics source must not take
the node out of the fleet view.

Vitals clamp (review fix, T1->T3): cpu_pct/mem_pct/disk_pct are clamped to
[0.0, 100.0] before being handed to fleet.sign_snapshot(). A multi-core CPU%
reading (>100) or a transient negative/garbage reading would otherwise fail
MetricSnapshot's ge=0/le=100 validators and silently drop the node from the
fleet. load1 is intentionally NOT clamped (load averages routinely exceed 100
on busy multi-core boxes and the model only requires ge=0).
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

METRICS_CACHE_PATH_ENV = "METRICS_CACHE_PATH"
DEFAULT_METRICS_CACHE_PATH = "/var/cache/secubox/metrics-cache.json"

ANNUAIRE_DB_PATH_ENV = "ANNUAIRE_DB_PATH"
DEFAULT_ANNUAIRE_DB_PATH = "/var/lib/secubox/annuaire/journal.db"

_ZERO_COUNTERS = {"bans": 0, "assist_sessions": 0, "soc_alerts": 0}


# ---------------------------------------------------------------------------
# small numeric helpers
# ---------------------------------------------------------------------------

def _num(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _clamp_pct(v: Any) -> float:
    """Clamp a percentage-shaped reading to [0.0, 100.0] (fail-safe on bad input)."""
    return max(0.0, min(100.0, _num(v)))


# ---------------------------------------------------------------------------
# default readers — production path
# ---------------------------------------------------------------------------

def _default_cache_reader() -> Dict[str, Any]:
    """Best-effort read of /var/cache/secubox/metrics-cache.json (secubox-metrics'
    build_cache() output: {"overview": {...}, "waf": {...}, "connections": {...}}).

    Maps the "overview" sub-dict's cpu_pct/mem_pct/uptime/load fields; any field
    not present (e.g. disk_pct — not currently written by secubox-metrics)
    defaults to 0. Never raises: missing file, malformed JSON, or unexpected
    shape all degrade to an all-zero reading.
    """
    zero = {"cpu_pct": 0.0, "mem_pct": 0.0, "disk_pct": 0.0, "load1": 0.0, "uptime_s": 0}
    path = os.environ.get(METRICS_CACHE_PATH_ENV, DEFAULT_METRICS_CACHE_PATH)
    try:
        with open(path) as f:
            data = json.load(f)
        overview = data.get("overview", {}) if isinstance(data, dict) else {}
        if not isinstance(overview, dict):
            overview = {}
        load_str = str(overview.get("load", "0") or "0").split()
        load1 = _num(load_str[0]) if load_str else 0.0
        return {
            "cpu_pct": _num(overview.get("cpu_pct", 0)),
            "mem_pct": _num(overview.get("mem_pct", 0)),
            "disk_pct": _num(overview.get("disk_pct", 0)),
            "load1": load1,
            "uptime_s": int(_num(overview.get("uptime", 0))),
        }
    except Exception:
        return zero


def _default_unit_lister() -> Tuple[int, List[str]]:
    """List secubox-* service units via systemctl; (modules_up, modules_down[:20]).

    "down" = any listed secubox-* unit whose ACTIVE column isn't "active".
    Never raises: a missing systemctl binary or unexpected output degrades
    to (0, []).
    """
    try:
        proc = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all",
             "--plain", "--no-legend", "secubox-*"],
            capture_output=True, text=True, timeout=5, shell=False,
        )
        up = 0
        down: List[str] = []
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if not parts:
                continue
            unit = parts[0]
            active = parts[2] if len(parts) > 2 else ""
            if active == "active":
                up += 1
            else:
                down.append(unit)
        return up, down[:20]
    except Exception:
        return 0, []


def _default_counter_reader() -> Dict[str, int]:
    """Best-effort {bans, assist_sessions, soc_alerts} from the local journal.

    Read-only open of the annuaire journal. If the DB doesn't exist yet (node
    not yet initialized) or any step fails, degrades to zeros — never raises.
    soc_alerts has no clean source yet and stays 0.
    """
    counters = dict(_ZERO_COUNTERS)
    db_path = os.environ.get(ANNUAIRE_DB_PATH_ENV, DEFAULT_ANNUAIRE_DB_PATH)
    if not os.path.exists(db_path):
        return counters
    try:
        from . import verbs, assist_match
        from .log import Journal
        from .model import now_rfc3339

        journal = Journal(db_path)
        try:
            counters["bans"] = len(verbs.banned_ips(journal))
        except Exception:
            pass
        try:
            entries = list(journal.iter_entries())
            counters["assist_sessions"] = len(
                assist_match.active_open_requests(entries, now_rfc3339())
            )
        except Exception:
            pass
    except Exception:
        pass
    return counters


# ---------------------------------------------------------------------------
# collect_snapshot — the injectable-reader entry point
# ---------------------------------------------------------------------------

def collect_snapshot(
    node_did: str,
    hostname: str,
    *,
    cache_reader=_default_cache_reader,
    unit_lister=_default_unit_lister,
    counter_reader=_default_counter_reader,
) -> Dict[str, Any]:
    """Assemble a MetricSnapshot fields dict (WITHOUT sig/signer_*).

    Never raises — each reader is individually guarded and a failure there
    degrades to safe zero values rather than aborting the publish cycle.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        cache = cache_reader()
        if not isinstance(cache, dict):
            cache = {}
    except Exception:
        cache = {}

    cpu_pct = _clamp_pct(cache.get("cpu_pct", 0))
    mem_pct = _clamp_pct(cache.get("mem_pct", 0))
    disk_pct = _clamp_pct(cache.get("disk_pct", 0))
    load1 = max(0.0, _num(cache.get("load1", 0)))  # NOT clamped to 100 — load can exceed it
    uptime_s = max(0, int(_num(cache.get("uptime_s", 0))))

    try:
        modules_up, modules_down = unit_lister()
    except Exception:
        modules_up, modules_down = 0, []
    modules_up = max(0, int(_num(modules_up)))
    try:
        modules_down = list(modules_down)[:20]
    except Exception:
        modules_down = []

    try:
        counters_in = counter_reader()
        if not isinstance(counters_in, dict):
            counters_in = {}
    except Exception:
        counters_in = {}
    counters = {
        "bans": max(0, int(_num(counters_in.get("bans", 0)))),
        "assist_sessions": max(0, int(_num(counters_in.get("assist_sessions", 0)))),
        "soc_alerts": max(0, int(_num(counters_in.get("soc_alerts", 0)))),
    }

    return {
        "node_did": node_did,
        "hostname": hostname,
        "ts": ts,
        "cpu_pct": cpu_pct,
        "mem_pct": mem_pct,
        "disk_pct": disk_pct,
        "load1": load1,
        "uptime_s": uptime_s,
        "modules_up": modules_up,
        "modules_down": modules_down,
        "counters": counters,
        "issued_by": node_did,
    }
