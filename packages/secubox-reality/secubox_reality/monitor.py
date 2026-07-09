# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — MIND stage: volume-guard decisioning
CyberMind — https://cybermind.fr

Queries cumulative traffic counters from each running egress point's
loopback ``StatsService`` (via ``xray api statsquery``), samples them into
SQLite (ROOT), and applies a sliding-window volume-guard: soft warn / hard
disable. Xray counters are CUMULATIVE (reset only on process restart), so
the per-window delta is computed as ``max(value) - min(value)`` across the
samples captured inside the window — NOT a simple last-sample read.

Caveat: if the xray instance restarts mid-window (counters reset to 0),
max-min under-counts that window's true usage. This is a known limitation
of the max-min approach and is accepted per spec; a monotonic-aware delta
(summing only positive deltas and treating any decrease as a reset-then-
recount) would close the gap but is out of scope here.

Invoked every 5 minutes by ``secubox-reality-monitor.timer`` ->
``secubox-reality-monitor.service`` (oneshot), which runs
``python3 -m secubox_reality.monitor``.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

from . import service, store
from .models import GuardConfig
from .xray import API_LISTEN, API_PORT, write_config_atomic

XRAY_BIN = "xray"
_TIMEOUT = 10

GB = 1024 ** 3

GUARD_CONFIG_PATH = f"{service.CONFIG_DIR}/guard.json"


def load_guard_config(path: str = GUARD_CONFIG_PATH) -> GuardConfig:
    """Load the operator-tunable volume-guard policy from
    ``/etc/secubox/reality/guard.json``, falling back to defaults if the
    file is absent or unreadable (never raises)."""
    try:
        with open(path, "r") as fh:
            return GuardConfig(**json.load(fh))
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError, ValueError):
        return GuardConfig()


def save_guard_config(guard: GuardConfig, path: str = GUARD_CONFIG_PATH) -> None:
    write_config_atomic(path, guard.model_dump())


class MonitorError(RuntimeError):
    pass


# --- stats collection --------------------------------------------------


def query_stats(api_addr: str = f"{API_LISTEN}:{API_PORT}", xray_bin: str = XRAY_BIN) -> Dict[str, int]:
    """Query cumulative uplink/downlink counters via ``xray api statsquery``
    against the loopback StatsService API inbound. Returns
    ``{"uplink": int, "downlink": int}`` summed across all matching stats.

    Never raises for a stopped/unreachable instance — returns zeros so the
    caller can skip sampling gracefully.
    """
    try:
        proc = subprocess.run(
            [xray_bin, "api", "statsquery", f"--server={api_addr}", "-pattern", ""],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"uplink": 0, "downlink": 0}

    if proc.returncode != 0 or not proc.stdout.strip():
        return {"uplink": 0, "downlink": 0}

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"uplink": 0, "downlink": 0}

    uplink = 0
    downlink = 0
    for stat in data.get("stat", []):
        name = stat.get("name", "")
        value = int(stat.get("value", 0))
        if "uplink" in name:
            uplink += value
        elif "downlink" in name:
            downlink += value
    return {"uplink": uplink, "downlink": downlink}


def sample_server(server_id: str, path: str = store.DEFAULT_DB_PATH, xray_bin: str = XRAY_BIN) -> None:
    st = service.status_instance(server_id)
    if not st["running"]:
        return
    counters = query_stats(xray_bin=xray_bin)
    store.insert_stats_sample(server_id, counters["uplink"], counters["downlink"], path=path)


# --- MIND: sliding-window delta + guard decision ----------------------------


def compute_window_delta(samples: List[Dict[str, Any]]) -> Dict[str, int]:
    """Per spec: delta = max(value) - min(value) across window samples,
    computed independently for uplink and downlink.
    """
    if not samples:
        return {"uplink": 0, "downlink": 0}
    uplinks = [s["uplink"] for s in samples]
    downlinks = [s["downlink"] for s in samples]
    return {
        "uplink": max(uplinks) - min(uplinks),
        "downlink": max(downlinks) - min(downlinks),
    }


def check_volume_guard(
    server_id: str,
    guard: GuardConfig,
    path: str = store.DEFAULT_DB_PATH,
) -> Dict[str, Any]:
    """Evaluate the volume-guard for one server and take action if the hard
    ceiling is crossed. Returns a report dict; never raises on the "over
    limit" case — that is a normal, expected outcome, not an error.
    """
    since = time.time() - guard.window_hours * 3600
    samples = store.get_stats_window(server_id, since, path=path)
    delta = compute_window_delta(samples)
    total_bytes = delta["uplink"] + delta["downlink"]
    total_gb = total_bytes / GB

    soft_hit = total_gb >= guard.soft_gb
    hard_hit = total_gb >= guard.hard_gb

    action_taken: Optional[str] = None
    if hard_hit and guard.action == "disable":
        # DISABLE = stop the instance WITHOUT destroying it: keys, config
        # and DB row (i.e. the IP + identity) survive so it can be
        # restarted once the operator raises the guard or a new window
        # opens.
        service.stop_instance(server_id)
        store.update_server_status(server_id, "disabled_volume_guard", path=path)
        action_taken = "disabled"

    return {
        "server_id": server_id,
        "window_hours": guard.window_hours,
        "uplink_bytes": delta["uplink"],
        "downlink_bytes": delta["downlink"],
        "total_gb": round(total_gb, 3),
        "soft_gb": guard.soft_gb,
        "hard_gb": guard.hard_gb,
        "soft_hit": soft_hit,
        "hard_hit": hard_hit,
        "action_taken": action_taken,
    }


def run_all(guard: GuardConfig, path: str = store.DEFAULT_DB_PATH, xray_bin: str = XRAY_BIN) -> List[Dict[str, Any]]:
    """Sample every server and evaluate the guard — the timer-driven entry
    point (also used directly by ``router.py``'s GET /stats)."""
    reports = []
    for srv in store.list_servers(path=path):
        sample_server(srv["id"], path=path, xray_bin=xray_bin)
        reports.append(check_volume_guard(srv["id"], guard, path=path))
    return reports


def main() -> int:
    """CLI entry point for the systemd timer/oneshot service."""
    store.init_db()
    guard = load_guard_config()
    reports = run_all(guard)
    for r in reports:
        if r["action_taken"]:
            print(f"[secubox-reality] volume-guard DISABLED {r['server_id']}: {r['total_gb']}GB "
                  f"(hard={r['hard_gb']}GB)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
