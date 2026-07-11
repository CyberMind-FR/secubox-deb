# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""WAF/HAProxy routing for published sites — all privileged work is delegated
to `secubox-publishctl`. Replaces the retired `sync_mitmproxy_routes` (which
wrote the dead mitmproxy-LXC route file)."""
from __future__ import annotations

import json
import subprocess

PUBLISHCTL = "/usr/sbin/secubox-publishctl"


def merge_route(existing: dict, domain: str, ip: str, port: int) -> dict:
    out = dict(existing)
    out[domain] = [ip, int(port)]
    return out


def _sudo_publishctl(verb: str, *args: str) -> dict:
    try:
        p = subprocess.run(["sudo", "-n", PUBLISHCTL, verb, *args],
                           capture_output=True, text=True, timeout=120)
        try:
            return json.loads(p.stdout.strip() or "{}")
        except json.JSONDecodeError:
            return {"ok": False, "detail": (p.stderr or p.stdout).strip()[:200]}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"ok": False, "detail": str(e)}


def apply_route(domain: str, port: int = 8900, runner=_sudo_publishctl) -> dict:
    vhost = runner("vhost-add", domain)
    waf = runner("waf-route", domain, str(port))
    return {"route_ok": bool(vhost.get("ok")) and bool(waf.get("ok")),
            "vhost": vhost, "waf": waf}
