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


# `haproxyctl vhost add` regenere la configuration HAProxy ENTIERE (~400 vhosts)
# puis la valide : 1 min 02 s mesurees sur gk2 pour ajouter un seul vhost. Le
# budget de 120 s etait donc frole a chaque appel et franchi des que la board
# travaillait — l'etape etait declaree en echec alors qu'elle avait abouti.
#
# Un depassement reste SANS DANGER : `cmd_generate` ecrit dans un fichier
# temporaire, valide, et n'installe qu'ensuite — une interruption laisse la
# configuration vivante intacte. On peut donc allonger sans risque.
DELAI_PUBLISHCTL = 300


def _sudo_publishctl(verb: str, *args: str) -> dict:
    try:
        p = subprocess.run(["sudo", "-n", PUBLISHCTL, verb, *args],
                           capture_output=True, text=True,
                           timeout=DELAI_PUBLISHCTL)
        try:
            return json.loads(p.stdout.strip() or "{}")
        except json.JSONDecodeError:
            return {"ok": False, "detail": (p.stderr or p.stdout).strip()[:200]}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"ok": False, "detail": str(e)}


def apply_route(domain: str, port: int = 8900, runner=_sudo_publishctl) -> dict:
    vhost = runner("vhost-add", domain)
    waf = runner("waf-route", domain, str(port))
    # The WAF route file is the OPERATIVE mechanism: sbxwaf serves a host iff it
    # is in that file, and HAProxy's `default_backend mitmproxy_inspector` already
    # sends TLS traffic to the WAF backend. `haproxyctl vhost add` is advisory
    # (belt-and-braces for setups without that default) and is blocked by
    # haproxyctl's drift-guard on a hand-migrated board — so it must NOT gate
    # success. route_ok reflects the WAF route only; vhost detail is still returned.
    return {"route_ok": bool(waf.get("ok")),
            "vhost": vhost, "waf": waf}
