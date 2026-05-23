# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-zigbee :: host FastAPI control plane.

zigbee2mqtt runs in LXC at 10.100.0.111 (br-lxc). This API is on the host,
on Unix socket /run/secubox/zigbee.sock, reverse-proxied at /api/v1/zigbee/
by the canonical hub vhost.

v2.4.0 surface (minimum viable):
  GET  /components   — three-fold component states
  GET  /status       — overall green/yellow/red
  GET  /access       — frontend + mqtt access points
  GET  /healthz      — cheap liveness probe

Deferred to v2.5 (Z2MBridge async pattern): /devices, /devices/{id},
/topology, /network, /permit_join, /rename, /bind, /ota/*.
"""

import json
import os
import socket
import subprocess
from pathlib import Path

from fastapi import FastAPI

LXC_NAME = os.environ.get("SECUBOX_LXC_NAME", "zigbee")
LXC_IP = os.environ.get("SECUBOX_LXC_IP", "10.100.0.111")
LXC_PATH = os.environ.get("SECUBOX_LXC_PATH", "/data/lxc")
FRONTEND_PORT = int(os.environ.get("SECUBOX_Z2M_FRONTEND_PORT", "8080"))
MQTT_LXC_IP = os.environ.get("SECUBOX_MQTT_LXC_IP", "10.100.0.110")
MQTT_PORT = int(os.environ.get("SECUBOX_MQTT_PORT", "1883"))
SECRETS_DIR = Path(os.environ.get("SECUBOX_SECRETS_DIR", "/etc/secubox/secrets"))
# v2.5.8: the public SSO-gated vhost that nginx + Authelia front for
# the zigbee2mqtt UI. Operators reach it from outside the LAN; the
# /access list now includes it explicitly.
PUBLIC_URL = os.environ.get("SECUBOX_ZIGBEE_PUBLIC_URL", "https://zigbee.gk2.secubox.in/")

app = FastAPI(
    title="SecuBox Zigbee",
    description="zigbee2mqtt coordinator control plane (MIND layer)",
    version="2.5.8",
)


def _lxc_state() -> str:
    """Infer LXC state without lxc-info (unprivileged user can't call it).
    See secubox-mqtt #240 commit for the rationale."""
    rootfs = Path(LXC_PATH) / LXC_NAME
    try:
        exists = rootfs.exists()
    except PermissionError:
        exists = True
    if not exists:
        return "absent"
    # TCP probe the z2m frontend; if it answers, daemon is up + LXC is up.
    try:
        with socket.create_connection((LXC_IP, FRONTEND_PORT), timeout=1.0):
            return "running"
    except OSError:
        # Frontend may be down (radio absent, z2m crash-loop). The LXC may
        # still be running. Fall back to a probe on the gateway 10.100.0.1
        # — if we can't reach that, the host networking is broken anyway.
        return "stopped"


def _radio_present() -> bool:
    return Path("/dev/secubox-zgb").exists()


def _z2m_running() -> bool:
    """TCP probe on the z2m frontend port — z2m only opens it after start."""
    try:
        with socket.create_connection((LXC_IP, FRONTEND_PORT), timeout=1.0):
            return True
    except OSError:
        return False


def _bridge_state() -> str:
    """Read the retained zigbee2mqtt/bridge/state topic via mosquitto_sub."""
    pw_file = SECRETS_DIR / "mqtt-z2m"
    if not pw_file.exists():
        return "no-creds"
    pw = pw_file.read_text().strip()
    try:
        proc = subprocess.run(
            ["mosquitto_sub", "-h", MQTT_LXC_IP, "-p", str(MQTT_PORT),
             "-u", "z2m", "-P", pw,
             "-t", "zigbee2mqtt/bridge/state", "-C", "1", "-W", "2"],
            capture_output=True, text=True, timeout=4,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return "unknown"
    if proc.returncode != 0 or not proc.stdout.strip():
        return "unknown"
    try:
        obj = json.loads(proc.stdout.strip())
        return obj.get("state", "unknown")
    except json.JSONDecodeError:
        # z2m 1.x published the bare string. 2.x publishes JSON.
        return proc.stdout.strip()


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/components")
def components() -> dict:
    lxc_st = _lxc_state()
    daemon_st = "running" if _z2m_running() else "stopped"
    dev_st = "present" if _radio_present() else "absent"
    bridge_st = _bridge_state()
    return {
        "module": "zigbee",
        "version": "2.4.0",
        "components": [
            {"name": "lxc", "state": lxc_st, "detail": f"{LXC_NAME} @ {LXC_IP} on br-lxc"},
            {"name": "device", "state": dev_st, "detail": "/dev/secubox-zgb"},
            {"name": "daemon", "state": daemon_st, "detail": f"zigbee2mqtt frontend :{FRONTEND_PORT}"},
            {"name": "bridge", "state": bridge_st, "detail": f"zigbee2mqtt/bridge/state @ {MQTT_LXC_IP}:{MQTT_PORT}"},
        ],
    }


@app.get("/status")
def status() -> dict:
    c = components()
    s = {x["name"]: x["state"] for x in c["components"]}
    if s.get("lxc") == "running" and s.get("daemon") == "running" \
       and s.get("device") == "present" and s.get("bridge") == "online":
        overall = "green"
    elif s.get("lxc") == "running" and s.get("daemon") == "running":
        # daemon up but no radio — expected on a board without dongle.
        overall = "yellow"
    elif s.get("lxc") == "running":
        overall = "yellow"
    else:
        overall = "red"
    return {"module": "zigbee", "version": "2.4.0", "overall": overall, "states": s}


@app.get("/access")
def access() -> dict:
    # v2.5.8: field renamed `endpoint` → `url` so the frontend's
    # `a.url` access actually finds a value (previously "lan:
    # undefined" rendered because the JS lookup missed). Public SSO-
    # gated vhost added as the first entry — that's the one operators
    # use from outside the LAN.
    return {
        "module": "zigbee",
        "access": [
            {"url": PUBLIC_URL,
             "scope": "public", "auth": "Authelia SSO"},
            {"url": f"http://{LXC_IP}:{FRONTEND_PORT}/",
             "scope": "lan", "auth": "none (LAN-only)"},
            {"url": f"mqtt://{MQTT_LXC_IP}:{MQTT_PORT} (zigbee2mqtt/#)",
             "scope": "lan-mqtt", "auth": "z2m user"},
        ],
    }


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "module": "zigbee", "version": "2.4.0"}
