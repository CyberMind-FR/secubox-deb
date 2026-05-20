# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-rbs-sensor :: host FastAPI control plane.

Host-resident (NO LXC — the modem is a host USB device). Listens on the
Unix socket /run/secubox/rbs-sensor.sock, reverse-proxied at /api/v1/rbs-sensor/
by the canonical hub vhost.

v0.1.0 surface (scaffold):
  GET  /status        — components + captures_subscriber_identifiers flag
  GET  /components    — modem / observer / actuator / host-api states
  GET  /servingcell   — latest serving CellObservation (None when modem absent)
  GET  /neighbours    — latest NeighbourObservation list
  GET  /access        — endpoints exposed
  POST /mitigate/lte-only / /mitigate/rf-off / /restore
  GET  /healthz

OPAD invariant proof: /status returns captures_subscriber_identifiers=false.
Auditor can verify without inspecting source.
"""

from __future__ import annotations

from dataclasses import asdict
import os
import sys

from fastapi import FastAPI, HTTPException

# Make sibling lib importable when launched via uvicorn api.main:app from
# /usr/lib/secubox/rbs-sensor — debian/rules installs lib/ as a sibling.
sys.path.insert(0, "/usr/lib/secubox/rbs-sensor/lib")

from rbs_sensor import CAPTURES_SUBSCRIBER_IDENTIFIERS  # noqa: E402
from rbs_sensor.ep06 import Ep06Actuator, Ep06Modem, Ep06Observer  # noqa: E402

app = FastAPI(
    title="SecuBox RBS Sensor",
    description="Rogue Base Station sensor — Quectel EP06-E backend (WALL layer)",
    version="0.1.0",
)

_modem = Ep06Modem()
_observer = Ep06Observer(modem=_modem)
_actuator = Ep06Actuator(modem=_modem)


def _modem_present() -> bool:
    try:
        return _modem.is_present()
    except (PermissionError, OSError):
        return False


def _host_api_running() -> bool:
    # Trivially true — if this endpoint is responding, the API is up.
    return True


@app.get("/status")
def status() -> dict:
    """Overall status + OPAD invariant flag.

    captures_subscriber_identifiers MUST be false. The test
    test_opad_invariant.py asserts this is exposed.
    """
    components = _components_list()
    states = {c["name"]: c["state"] for c in components}
    if states.get("modem") == "present" and states.get("observer") == "running":
        overall = "green"
    elif states.get("host-api") == "running":
        overall = "yellow"  # API up but no modem → scaffold state, expected
    else:
        overall = "red"
    return {
        "module": "rbs-sensor",
        "version": "0.1.0",
        "overall": overall,
        "states": states,
        "captures_subscriber_identifiers": CAPTURES_SUBSCRIBER_IDENTIFIERS,
    }


def _components_list() -> list[dict]:
    modem_st = "present" if _modem_present() else "absent"
    obs_st = "running" if _modem_present() else "idle"
    act_st = "ready" if _modem_present() else "idle"
    return [
        {"name": "modem", "state": modem_st,
         "detail": "Quectel EP06-E (USB 2c7c:0306) — /dev/ttyUSB*"},
        {"name": "observer", "state": obs_st,
         "detail": "Ep06Observer (AT poll loop)"},
        {"name": "actuator", "state": act_st,
         "detail": "Ep06Actuator (lte-only / rf-off / restore)"},
        {"name": "host-api", "state": "running" if _host_api_running() else "stopped",
         "detail": "secubox-rbs-sensor.service (uvicorn @ /run/secubox/rbs-sensor.sock)"},
    ]


@app.get("/components")
def components() -> dict:
    return {"module": "rbs-sensor", "version": "0.1.0",
            "components": _components_list()}


@app.get("/access")
def access() -> dict:
    return {
        "module": "rbs-sensor",
        "access": [
            {"endpoint": "/run/secubox/rbs-sensor.sock", "scope": "host-only",
             "auth": "Unix socket (root + secubox group)"},
            {"endpoint": "/api/v1/rbs-sensor/ (via canonical hub vhost)",
             "scope": "lan", "auth": "JWT (Authelia / secubox-zkp-auth)"},
        ],
    }


@app.get("/servingcell")
def serving_cell() -> dict:
    obs = _observer.serving_cell()
    if obs is None:
        if not _modem_present():
            raise HTTPException(503, "modem-absent")
        # Modem present but no current camp.
        return {"observation": None, "reason": "not-camped"}
    return {"observation": asdict(obs)}


@app.get("/neighbours")
def neighbours() -> dict:
    if not _modem_present():
        raise HTTPException(503, "modem-absent")
    return {"observations": [asdict(n) for n in _observer.neighbours()]}


@app.post("/mitigate/lte-only")
async def mitigate_lte_only() -> dict:
    return await _actuator.mitigate_lte_only()


@app.post("/mitigate/rf-off")
async def mitigate_rf_off() -> dict:
    return await _actuator.mitigate_rf_off()


@app.post("/restore")
async def restore() -> dict:
    return await _actuator.restore()


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "module": "rbs-sensor", "version": "0.1.0",
            "captures_subscriber_identifiers": CAPTURES_SUBSCRIBER_IDENTIFIERS}
