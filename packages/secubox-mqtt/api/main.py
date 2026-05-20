# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-mqtt :: host FastAPI control plane.

Mosquitto runs in LXC at 10.100.0.110 (br-lxc). This API is on the host,
on Unix socket /run/secubox/mqtt.sock, reverse-proxied at /api/v1/mqtt/
by the canonical hub vhost. Authentication is provided by the canonical
SecuBox JWT middleware (handled at the nginx/Authelia layer).
"""

import os
import socket
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException

LXC_NAME = os.environ.get("SECUBOX_LXC_NAME", "mqtt")
LXC_IP = os.environ.get("SECUBOX_LXC_IP", "10.100.0.110")
LXC_PATH = os.environ.get("SECUBOX_LXC_PATH", "/data/lxc")
MQTT_PORT = int(os.environ.get("SECUBOX_MQTT_PORT", "1883"))
SECRETS_DIR = Path(os.environ.get("SECUBOX_SECRETS_DIR", "/etc/secubox/secrets"))

app = FastAPI(
    title="SecuBox MQTT",
    description="Mosquitto broker control plane (WALL layer)",
    version="2.4.0",
)


def _lxc_state() -> str:
    """Infer LXC state without lxc-info — that requires root, and this API
    runs as the unprivileged `secubox` user. The cheapest signal that
    works for an unprivileged caller: open a TCP connection to
    LXC_IP:MQTT_PORT. The LXC rootfs at /data/lxc/<name>/ is often
    chmod 0770 owned by the LXC mapped uid 100000, so stat() throws
    PermissionError — we treat that as "present, run TCP probe."

    Returns 'running' / 'stopped' / 'absent'.
    """
    rootfs = Path(LXC_PATH) / LXC_NAME
    try:
        exists = rootfs.exists()
    except PermissionError:
        # /data/lxc/<name>/ is unreadable by us — but it exists, so fall through.
        exists = True
    if not exists:
        return "absent"
    try:
        with socket.create_connection((LXC_IP, MQTT_PORT), timeout=1.0):
            return "running"
    except OSError:
        return "stopped"


def _broker_running() -> bool:
    """A TCP open on LXC_IP:1883 is equivalent to mosquitto being up — there's
    only one listener in the LXC (the Debian-default 127.0.0.1 listener is
    inside the LXC, not on 10.100.0.110)."""
    try:
        with socket.create_connection((LXC_IP, MQTT_PORT), timeout=1.0):
            return True
    except OSError:
        return False


def _broker_healthy() -> bool:
    """Pub a marker on secubox/healthcheck; success means the broker accepts auth."""
    pw_file = SECRETS_DIR / "mqtt-secubox-api"
    if not pw_file.exists():
        return False
    pw = pw_file.read_text().strip()
    try:
        rc = subprocess.run(
            ["mosquitto_pub", "-h", LXC_IP, "-p", str(MQTT_PORT),
             "-u", "secubox-api", "-P", pw,
             "-t", "secubox/healthcheck", "-m", str(int(time.time()))],
            capture_output=True, text=True, timeout=3,
        ).returncode
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
    return rc == 0


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/components")
def components() -> dict:
    lxc_st = _lxc_state()
    broker_st = "running" if _broker_running() else "stopped"
    health_st = "ok" if _broker_healthy() else "degraded"
    return {
        "module": "mqtt",
        "version": "2.4.0",
        "components": [
            {"name": "lxc", "state": lxc_st, "detail": f"{LXC_NAME} @ {LXC_IP} on br-lxc"},
            {"name": "broker", "state": broker_st, "detail": f"mosquitto, port {MQTT_PORT}"},
            {"name": "health", "state": health_st, "detail": "pub round-trip via secubox-api"},
        ],
    }


@app.get("/status")
def status() -> dict:
    c = components()
    states = {x["name"]: x["state"] for x in c["components"]}
    if states.get("lxc") == "running" and states.get("broker") == "running" and states.get("health") == "ok":
        overall = "green"
    elif states.get("lxc") == "running":
        overall = "yellow"
    else:
        overall = "red"
    return {"module": "mqtt", "version": "2.4.0", "overall": overall, "states": states}


@app.get("/access")
def access() -> dict:
    """List ACL users + their topic globs.

    Reads from the host-side cache /etc/secubox/mqtt-acl.cached written
    by install-lxc.sh — we can't lxc-attach as the unprivileged `secubox`
    user. The cache is regenerated on every `mqttctl install`."""
    cache = Path("/etc/secubox/mqtt-acl.cached")
    if not cache.exists():
        raise HTTPException(503, "ACL cache absent — run 'mqttctl install' on the host")
    users = []
    current_user = None
    for raw in cache.read_text().splitlines():
        line = raw.strip()
        if line.startswith("user "):
            current_user = line.split(None, 1)[1].strip()
        elif current_user and line.startswith("topic "):
            parts = line.split(None, 2)
            mode = parts[1] if len(parts) >= 3 else "?"
            topic = parts[2] if len(parts) >= 3 else parts[1]
            users.append({"user": current_user, "mode": mode, "topic": topic, "scope": "lan"})
            current_user = None
    return {"module": "mqtt", "access": users}


@app.get("/healthz")
def healthz() -> dict:
    """Cheap liveness probe — doesn't poke the broker, just confirms FastAPI is alive."""
    return {"ok": True, "module": "mqtt", "version": "2.4.0"}
