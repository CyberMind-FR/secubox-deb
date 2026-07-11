# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — BOOT stage: templated instance lifecycle
CyberMind — https://cybermind.fr

Each egress point runs as its own hardened systemd instance,
``secubox-xray@<server_id>.service`` (unit template shipped in
``debian/secubox-xray@.service``: ``DynamicUser=yes``, ``ProtectSystem=strict``,
``AmbientCapabilities=CAP_NET_BIND_SERVICE``, ``NoNewPrivileges=yes``).

All functions here shell out to ``systemctl`` and are intentionally
synchronous (plain ``def``) — callers in ``router.py`` must NOT ``await``
them directly from an ``async def`` handler; FastAPI offloads plain-``def``
route handlers to a threadpool, which is the supported way to keep these
subprocess calls off the shared event loop.
"""
from __future__ import annotations

import subprocess
from typing import Any, Dict

SYSTEMCTL_BIN = "systemctl"
CONFIG_DIR = "/etc/secubox/reality"
_TIMEOUT = 15


class ServiceError(RuntimeError):
    pass


def instance_name(server_id: str) -> str:
    return f"secubox-xray@{server_id}"


def config_path(server_id: str) -> str:
    return f"{CONFIG_DIR}/{server_id}.json"


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    cmd = [SYSTEMCTL_BIN, *args]
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT, check=False
        )
    except FileNotFoundError as exc:
        raise ServiceError(f"systemctl not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ServiceError(f"systemctl {' '.join(args)} timed out") from exc


def start_instance(server_id: str) -> bool:
    proc = _systemctl("start", instance_name(server_id))
    return proc.returncode == 0


def stop_instance(server_id: str) -> bool:
    """Stop the instance WITHOUT disabling/destroying it — the config file,
    keys and DB row are all preserved so the egress point can be restarted
    later without re-provisioning (used by the volume-guard DISABLE action).
    """
    proc = _systemctl("stop", instance_name(server_id))
    return proc.returncode == 0


def enable_instance(server_id: str) -> bool:
    proc = _systemctl("enable", instance_name(server_id))
    return proc.returncode == 0


def disable_instance(server_id: str) -> bool:
    proc = _systemctl("disable", instance_name(server_id))
    return proc.returncode == 0


def restart_instance(server_id: str) -> bool:
    proc = _systemctl("restart", instance_name(server_id))
    return proc.returncode == 0


def status_instance(server_id: str) -> Dict[str, Any]:
    proc = _systemctl("is-active", instance_name(server_id))
    active = proc.stdout.strip()
    return {
        "unit": instance_name(server_id),
        "active": active,
        "running": active == "active",
    }


# --- BOOT: full provisioning flow -------------------------------------------


def boot_provision(server_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Write the instance's Xray config atomically, then enable + (re)start
    the templated unit. Returns the resulting status snapshot.
    """
    from . import xray

    xray.write_config_atomic(config_path(server_id), config)
    enable_instance(server_id)
    if not restart_instance(server_id):
        # restart on a never-started unit can fail on some systemd versions;
        # fall back to a plain start.
        start_instance(server_id)
    return status_instance(server_id)
