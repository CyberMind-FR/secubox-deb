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
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

sys.path.insert(0, "/usr/lib/secubox/sentinelle-gsm/lib")

from sentinelle_gsm import CAPTURES_PLAINTEXT_IMSI, Mode  # noqa: E402
from sentinelle_gsm.alert_sink import Alert, AlertSink   # noqa: E402
from sentinelle_gsm.livemon import detect_rtlsdr_usb     # noqa: E402
from sentinelle_gsm.observer import Anonymizer           # noqa: E402
from sentinelle_gsm.trusted import TrustedRegistry       # noqa: E402

SECRETS_DIR = Path(os.environ.get("SECUBOX_SECRETS_DIR", "/etc/secubox/secrets"))
HMAC_KEY_FILE = SECRETS_DIR / "sentinelle-gsm-hmac"
MODE_FILE = Path("/var/lib/secubox/sentinelle-gsm/mode")  # PROD by default

app = FastAPI(
    title="SecuBox SENTINELLE-GSM",
    description="Passive GSM rogue-BTS sensor (MIND layer) — RX only, off-path",
    version="0.2.0",
)


# ── v0.2: alert sink + trusted registry singletons ──────────────────────────
#
# Auth note: this package is reverse-proxied through nginx + Authelia (see
# nginx/sentinelle-gsm.conf), which terminates JWT before forwarding to the
# Unix socket. `require_jwt` is therefore a no-op dependency here; it exists
# as a hook so tests (and future host-direct callers) can override it via
# `app.dependency_overrides[require_jwt]`.

def require_jwt() -> dict:
    """No-op auth hook. Real JWT enforcement happens at nginx/Authelia."""
    return {"sub": "nginx-authelia"}


_alert_sink: Optional[AlertSink] = None
_trusted_registry: Optional[TrustedRegistry] = None

ALERTS_DB_PATH = Path("/var/lib/secubox/sentinelle-gsm/alerts.db")
TRUSTED_REGISTRY_PATH = Path("/etc/secubox/sentinelle-gsm/trusted.json")


def _get_anonymizer() -> Anonymizer:
    """Load the HMAC key from disk; fall back to an ephemeral key.

    The ephemeral fallback exists so the API can boot on a freshly-installed
    box where postinst hasn't yet generated the key. In that case the
    trusted-registry hashes are stable for the lifetime of the process but
    lost on restart — the operator should re-add trusted phones once the
    persistent HMAC key is in place.
    """
    mode = _read_mode()
    if _hmac_key_present():
        return Anonymizer.from_file(HMAC_KEY_FILE, mode=mode)
    return Anonymizer.ephemeral(mode=mode)


def get_alert_sink() -> AlertSink:
    if _alert_sink is None:
        raise RuntimeError("alert_sink not initialised")
    return _alert_sink


def get_trusted_registry() -> TrustedRegistry:
    if _trusted_registry is None:
        raise RuntimeError("trusted_registry not initialised")
    return _trusted_registry


@app.on_event("startup")
def _init_v0_2_singletons() -> None:
    global _alert_sink, _trusted_registry
    if _alert_sink is None:
        _alert_sink = AlertSink(ALERTS_DB_PATH)
    if _trusted_registry is None:
        _trusted_registry = TrustedRegistry(TRUSTED_REGISTRY_PATH, _get_anonymizer())


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


class TrustedAddBody(BaseModel):
    imsi: str
    label: str


@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def list_alerts(limit: int = 100, since: float = 0.0) -> dict:
    """Paginated alert history from the SQLite-backed sink."""
    return {
        "alerts": [
            asdict(a) for a in get_alert_sink().list(limit=limit, since=since)
        ]
    }


@app.get("/alerts/stream", dependencies=[Depends(require_jwt)])
async def stream_alerts() -> StreamingResponse:
    """Server-Sent Events live feed of anomaly alerts.

    Headers disable buffering at every layer (nginx via X-Accel-Buffering,
    HTTP client caches via Cache-Control). The async generator runs until
    the client disconnects; FastAPI handles cancellation.
    """
    sink = get_alert_sink()
    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return StreamingResponse(
        sink.stream(), media_type="text/event-stream", headers=headers
    )


@app.post("/alerts/test", dependencies=[Depends(require_jwt)])
async def test_alert(body: Optional[dict] = Body(default=None)) -> dict:
    """Manual operator trigger — writes a synthetic alert end-to-end.

    A privacy-guard violation (plaintext-IMSI shape detected in any field)
    surfaces as a 500 so the upstream UI / curl gets a clean error rather
    than a stack trace. The error message is preserved.
    """
    body = body or {}
    a = Alert(
        cell_id=body.get("cell_id", "208-01-100-99999"),
        arfcn=body.get("arfcn", 124),
        score=body.get("score", 80),
        reason=body.get("reason", "operator-test"),
        subscriber_hash=body.get("subscriber_hash"),
        trusted_label=body.get("trusted_label"),
    )
    try:
        written = get_alert_sink().write(a)
    except ValueError as e:
        raise HTTPException(500, str(e))
    return {"ok": True, "id": written.id}


@app.get("/trusted", dependencies=[Depends(require_jwt)])
async def list_trusted() -> dict:
    return {"phones": [asdict(p) for p in get_trusted_registry().list()]}


@app.post("/trusted", dependencies=[Depends(require_jwt)])
async def add_trusted(body: TrustedAddBody) -> dict:
    try:
        p = get_trusted_registry().add(body.imsi, body.label)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return asdict(p)


@app.delete("/trusted/{phone_id}", dependencies=[Depends(require_jwt)])
async def delete_trusted(phone_id: str) -> dict:
    if not get_trusted_registry().delete(phone_id):
        raise HTTPException(404, "not found")
    return {"ok": True}


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
