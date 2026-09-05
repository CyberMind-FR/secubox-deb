#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Module Health Prober — Background service for module API health monitoring.
Writes buffered metrics to /var/cache/secubox/health/modules.json.

v2 (2026-05-27): switched from hardcoded 8-module list to auto-discovery from
/run/secubox/*.sock. Operator pointed out the dashboard "Module Health" was
showing 50% based on 4/8 tracked when the board actually runs 100+ modules.
The hardcoded list had drifted exactly like scripts/build-packages.sh did
(fixed in 561007fe). Discovery now scales with whatever services are
installed; no per-deploy maintenance.
"""

import asyncio
import json
import subprocess
import socket
from pathlib import Path
from datetime import datetime, timezone
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("module-prober")

CACHE_FILE = Path("/var/cache/secubox/health/modules.json")
SOCKET_DIR = Path("/run/secubox")

# Modules considered "critical" — overall=down on a critical module marks the
# whole board as degraded for SLA/alerting purposes. Everything else is
# treated as non-critical (cosmetic for the dashboard health %).
CRITICAL_MODULES = {
    "hub", "dpi", "haproxy", "vhost", "system", "core",
    "auth", "authelia", "portal", "users", "mail",
}


def discover_modules():
    """Auto-discover modules from /run/secubox/*.sock.

    Returns a dict keyed by module name (sock filename without .sock suffix)
    pointing to {socket, health, critical}. Critical flag comes from the
    static CRITICAL_MODULES allowlist above; everything else is non-critical.
    """
    modules = {}
    if not SOCKET_DIR.is_dir():
        return modules
    for sock_path in sorted(SOCKET_DIR.glob("*.sock")):
        name = sock_path.stem
        modules[name] = {
            "socket": sock_path.name,
            "health": "/health",  # convention: every secubox-* module exposes /health (e2989322)
            "critical": name in CRITICAL_MODULES,
        }
    return modules


def check_systemd_status(service_name):
    """Check if systemd service is active."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", f"secubox-{service_name}"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


def check_socket_exists(socket_name):
    socket_path = SOCKET_DIR / socket_name
    return socket_path.exists()


def check_api_health(socket_name, health_endpoint):
    """Check if the API on the socket responds 200 to GET <health_endpoint>."""
    socket_path = SOCKET_DIR / socket_name
    if not socket_path.exists():
        return False, "socket_missing"

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(str(socket_path))
        request = (
            f"GET {health_endpoint} HTTP/1.1\r\n"
            "Host: localhost\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(request.encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 8192:
                break
        sock.close()
        response_str = response.decode("utf-8", errors="ignore")
        if "HTTP/1.1 200" in response_str or "HTTP/1.0 200" in response_str:
            return True, "ok"
        if "HTTP/1.1 4" in response_str or "HTTP/1.0 4" in response_str:
            return False, "http_4xx"
        if "HTTP/1.1 5" in response_str or "HTTP/1.0 5" in response_str:
            return False, "http_5xx"
        return False, "no_200"
    except Exception as e:
        return False, str(e)[:80]


def probe_module(name, cfg):
    """Probe one module's three layers (systemd / socket / API)."""
    timestamp = datetime.now(timezone.utc).isoformat()

    systemd_active = check_systemd_status(name)
    socket_present = check_socket_exists(cfg["socket"])
    api_ok, api_detail = check_api_health(cfg["socket"], cfg["health"])

    layers = {
        "systemd": {
            "status": "ok" if systemd_active else "down",
            "detail": "active" if systemd_active else "inactive",
        },
        "socket": {
            "status": "ok" if socket_present else "down",
            "detail": "present" if socket_present else "missing",
        },
        "api": {
            "status": "ok" if api_ok else "down" if socket_present else "unknown",
            "detail": api_detail,
        },
    }

    # Overall rollup: all-3-ok → ok; some-down → degraded; all-down → down
    statuses = [l["status"] for l in layers.values()]
    if all(s == "ok" for s in statuses):
        overall = "ok"
    elif all(s in ("down",) for s in statuses):
        overall = "down"
    else:
        overall = "degraded"

    return {
        "name": name,
        "timestamp": timestamp,
        "critical": cfg.get("critical", False),
        "layers": layers,
        "overall": overall,
    }


def write_snapshot(modules_results):
    """Persist results to CACHE_FILE with pre-computed bucket counts."""
    total = len(modules_results)
    ok = sum(1 for m in modules_results.values() if m["overall"] == "ok")
    degraded = sum(1 for m in modules_results.values() if m["overall"] == "degraded")
    down = sum(1 for m in modules_results.values() if m["overall"] == "down")
    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "ok": ok,
        "degraded": degraded,
        "down": down,
        "health_pct": int(ok / max(total, 1) * 100),
        "modules": modules_results,
    }
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(snapshot, indent=2))
    tmp.replace(CACHE_FILE)


async def main_loop():
    interval = 60
    while True:
        try:
            modules = discover_modules()
            results = {name: probe_module(name, cfg) for name, cfg in modules.items()}
            write_snapshot(results)
            logger.info("probed %d modules", len(results))
        except Exception as e:
            logger.exception("probe loop error: %s", e)
        await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(main_loop())
