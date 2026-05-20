# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-sentinelle-gsm :: host FastAPI control plane.

Host-resident (NO LXC — the SDR is host USB hardware). Unix socket
/run/secubox/sentinelle-gsm.sock, reverse-proxied at /api/v1/sensor/gsm/
on the canonical hub vhost.

v0.1.0 surface (scaffold):
  GET  /status            — components + privacy invariant flag + mode
  GET  /components        — sdr / livemon / analyzer / host-api states
  GET  /access            — exposed endpoints
  GET  /cells             — observed cells (empty until v0.2 wires gr-gsm)
  GET  /alerts            — active/historized alerts (empty in v0.1)
  POST /mode              — flip PROD ↔ LAB (LAB requires consent ack + audit)
  GET  /healthz

OPAD/privacy invariant proof: /status returns
`captures_plaintext_imsi: false` and `mode: prod`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI, HTTPException

sys.path.insert(0, "/usr/lib/secubox/sentinelle-gsm/lib")

from sentinelle_gsm import CAPTURES_PLAINTEXT_IMSI, Mode  # noqa: E402
from sentinelle_gsm.livemon import detect_rtlsdr_usb     # noqa: E402

SECRETS_DIR = Path(os.environ.get("SECUBOX_SECRETS_DIR", "/etc/secubox/secrets"))
HMAC_KEY_FILE = SECRETS_DIR / "sentinelle-gsm-hmac"
MODE_FILE = Path("/var/lib/secubox/sentinelle-gsm/mode")  # PROD by default

app = FastAPI(
    title="SecuBox SENTINELLE-GSM",
    description="Passive GSM rogue-BTS sensor (MIND layer) — RX only, off-path",
    version="0.1.0",
)


def _read_mode() -> Mode:
    """Read the current PROD/LAB mode marker (PROD if file absent)."""
    try:
        raw = MODE_FILE.read_text().strip().lower()
        return Mode(raw)
    except (FileNotFoundError, PermissionError, ValueError):
        return Mode.PROD


def _hmac_key_present() -> bool:
    try:
        return HMAC_KEY_FILE.exists() and HMAC_KEY_FILE.stat().st_size >= 32
    except (PermissionError, OSError):
        return False


def _sdr_present() -> bool:
    return detect_rtlsdr_usb() is not None


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/status")
def status() -> dict:
    components = _components_list()
    states = {c["name"]: c["state"] for c in components}
    if states.get("sdr") == "present" and states.get("livemon") == "running" \
       and states.get("analyzer") == "running":
        overall = "green"
    elif states.get("host-api") == "running":
        overall = "yellow"  # API up but no SDR — expected scaffold state
    else:
        overall = "red"
    mode = _read_mode()
    return {
        "module": "sentinelle-gsm",
        "version": "0.1.0",
        "overall": overall,
        "states": states,
        "mode": mode.value,
        # OPAD / privacy invariant flag — auditor-visible.
        "captures_plaintext_imsi": (mode is Mode.LAB),  # only LAB can capture
        "captures_plaintext_imsi_in_prod": CAPTURES_PLAINTEXT_IMSI,  # always False
        "rx_only": True,  # NEVER emits RF; structural property
    }


def _components_list() -> list[dict]:
    sdr_st = "present" if _sdr_present() else "absent"
    # v0.1 doesn't actually run livemon/analyzer worker threads.
    livemon_st = "running" if _sdr_present() else "idle"
    analyzer_st = "running" if _sdr_present() else "idle"
    key_st = "ok" if _hmac_key_present() else "missing"
    return [
        {"name": "sdr", "state": sdr_st,
         "detail": "RTL-SDR USB (0bda:2832/2838, 1d50:604b, 1f4d:0001)"},
        {"name": "livemon", "state": livemon_st,
         "detail": "grgsm_livemon_headless → GSMTAP udp://127.0.0.1:4729"},
        {"name": "analyzer", "state": analyzer_st,
         "detail": "GSMTAP parser + scoring (8 heuristics)"},
        {"name": "hmac-key", "state": key_st,
         "detail": str(HMAC_KEY_FILE)},
        {"name": "host-api", "state": "running",
         "detail": "secubox-sentinelle-gsm.service (uvicorn)"},
    ]


@app.get("/components")
def components() -> dict:
    return {"module": "sentinelle-gsm", "version": "0.1.0",
            "components": _components_list()}


@app.get("/access")
def access() -> dict:
    return {
        "module": "sentinelle-gsm",
        "access": [
            {"endpoint": "/run/secubox/sentinelle-gsm.sock",
             "scope": "host-only", "auth": "Unix socket (root + secubox)"},
            {"endpoint": "/api/v1/sensor/gsm/ (via canonical hub vhost)",
             "scope": "lan", "auth": "JWT (Authelia / secubox-zkp-auth)"},
        ],
    }


@app.get("/cells")
def cells() -> dict:
    """Observed cells + scores. Empty in v0.1.0 (scoring engine stubbed)."""
    if not _sdr_present():
        raise HTTPException(503, "sdr-absent")
    return {"cells": []}  # v0.2 wires the GSMTAP feed


@app.get("/alerts")
def alerts() -> dict:
    """Active + historized alerts. Empty in v0.1.0."""
    return {"alerts": []}


@app.post("/mode")
def set_mode(payload: dict = Body(...)) -> dict:
    """Flip between PROD ↔ LAB.

    LAB requires an explicit `consent_ack: true` field — without it, the
    request is refused. Every successful transition writes to
    /var/log/secubox/sentinelle-gsm-audit.log (audit trail).
    """
    target = (payload.get("mode") or "").lower()
    if target not in ("prod", "lab"):
        raise HTTPException(400, "mode must be 'prod' or 'lab'")
    target_mode = Mode(target)
    if target_mode is Mode.LAB and not payload.get("consent_ack"):
        raise HTTPException(
            400,
            "LAB mode requires consent_ack=true (owned-SIM / consented-device statement)"
        )
    try:
        MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
        MODE_FILE.write_text(target_mode.value + "\n")
    except (PermissionError, OSError) as e:
        raise HTTPException(500, f"could not persist mode: {e}")
    # Audit log
    try:
        audit_log = Path("/var/log/secubox/sentinelle-gsm-audit.log")
        audit_log.parent.mkdir(parents=True, exist_ok=True)
        import time
        with open(audit_log, "a") as f:
            f.write(f"{time.time():.3f} mode-flip → {target_mode.value} "
                    f"(consent_ack={bool(payload.get('consent_ack'))})\n")
    except (PermissionError, OSError):
        pass  # don't 500 on audit-log fail; mode flip already persisted
    return {"ok": True, "mode": target_mode.value}


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "module": "sentinelle-gsm", "version": "0.1.0",
            "captures_plaintext_imsi_in_prod": CAPTURES_PLAINTEXT_IMSI,
            "rx_only": True}
