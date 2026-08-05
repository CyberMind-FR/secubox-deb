# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-jitsi — host control plane API (LXC-native).
CyberMind — https://cybermind.fr

FastAPI on /run/secubox/jitsi.sock, proxied by nginx at /api/v1/jitsi/.
DEDICATED socket (secubox-jitsi.service) — NOT the aggregator: this API sudo's
the root `jitsictl` actuator (needs NoNewPrivileges=no, which the aggregator
does not grant) and runs a background /status refresher on startup (mounted
sub-apps never get a lifespan on the aggregator loop).

Replaces the 1.0.0 API, which generated a docker-compose.yml and ran
docker/podman from inside the request path. Two rules that module broke and
this one keeps: modules run native in their LXC with their own systemd units,
and the WebUI performs no privileged work itself — every state change is
delegated to `jitsictl`, the single audited root surface.

WHAT WAS DELIBERATELY NOT CARRIED OVER from 1.0.0, and why:

  /rooms, /room/{name}, /room/{name}/close
      Jitsi does not expose room names through colibri. Those handlers
      answered "Room status not available via API" and, for close,
      {"success": false, "message": "requires Prosody admin module"} — an API
      surface that promised something it never delivered. Removed rather than
      re-implemented as the same stub. Real room control needs a Prosody admin
      module; that is a feature to design, not an endpoint to keep warm.

  /recordings, /jibri/*
      Recording needs jibri, which is not part of this deployment (it wants a
      full Chrome + ALSA loopback per recording — not something to run on this
      board unasked). Tracked in #985 rather than shipped inert.

  /auth, /config POST
      1.0.0 wrote its own TOML from the request body and told the operator to
      restart. Configuration here is declarative (/etc/secubox/jitsi.toml) and
      the domain is baked into four services at provisioning time by debconf
      preseed — a hostname changed through an API POST would leave prosody,
      jicofo, the videobridge and nginx disagreeing. Re-provisioning is the
      honest operation, and it belongs to the ctl.

Endpoints (all JWT-gated except /health):
  GET  /health          public liveness ({status, module})
  GET  /status          jitsictl status — 60 s double-cached (bg refresh)
  GET  /stats           jitsictl stats — live colibri counters
  POST /control         {action}        → jitsictl start|stop|restart
  POST /service/restart {unit}          → jitsictl service-restart <unit>
  POST /public-ip       {address}       → jitsictl set-public-ip <address>
  GET  /logs            ?unit=&lines=   → jitsictl logs
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from secubox_core.auth import require_jwt

VERSION = "2.0.0"

CTL = "/usr/sbin/jitsictl"

CACHE_DIR = Path("/var/cache/secubox/jitsi")
STATUS_CACHE_FILE = CACHE_DIR / "status.json"
STATUS_TTL = 60.0

# The units this API will name to the ctl. The ctl validates independently —
# this is not the security boundary, it is the API refusing to forward a value
# it already knows is meaningless, so the caller gets 400 instead of 500.
KNOWN_UNITS = ("prosody", "jicofo", "jitsi-videobridge2", "nginx")

log = logging.getLogger("secubox-jitsi")

app = FastAPI(
    title="SecuBox Jitsi",
    version=VERSION,
    root_path="/api/v1/jitsi",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_status_cache: Dict[str, Any] = {"data": None, "ts": 0.0}


# ── ctl runners ──────────────────────────────────────────────────────────────
def _run_ctl(*args: str, timeout: int = 30):
    """`sudo -n jitsictl <args>` → (returncode, stdout, stderr). Never raises:
    a missing/slow/erroring ctl must degrade the panel, not crash a handler."""
    try:
        p = subprocess.run(
            ["sudo", "-n", CTL, *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"jitsictl {' '.join(args)} timed out after {timeout}s"
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", f"jitsictl invocation failed: {exc}"


def _ctl_json(*args: str, timeout: int = 30) -> Dict[str, Any]:
    rc, out, err = _run_ctl(*args, timeout=timeout)
    if rc != 0:
        detail = (err or out or f"jitsictl exited {rc}").strip()[:500]
        raise HTTPException(status_code=500, detail=detail)
    out = out.strip()
    if not out:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail=f"jitsictl emitted non-JSON: {out[:300]!r}",
        )


# ── /status double-cache ─────────────────────────────────────────────────────
def _refresh_status() -> Dict[str, Any]:
    data = _ctl_json("status")
    _status_cache["data"] = data
    _status_cache["ts"] = time.time()
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        STATUS_CACHE_FILE.write_text(json.dumps(data))
    except OSError as exc:
        log.warning("status cache write failed: %s", exc)
    return data


async def _status_refresher() -> None:
    while True:
        try:
            await asyncio.to_thread(_refresh_status)
        except HTTPException as exc:
            log.warning("status refresh failed: %s", exc.detail)
        except Exception as exc:  # noqa: BLE001 — never let the loop die
            log.warning("status refresh error: %s", exc)
        await asyncio.sleep(STATUS_TTL)


@app.on_event("startup")
async def _startup() -> None:
    if _status_cache["data"] is None and STATUS_CACHE_FILE.is_file():
        try:
            _status_cache["data"] = json.loads(STATUS_CACHE_FILE.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    asyncio.create_task(_status_refresher())


# ── models ───────────────────────────────────────────────────────────────────
class ControlRequest(BaseModel):
    action: str


class ServiceRequest(BaseModel):
    unit: str


class PublicIPRequest(BaseModel):
    address: str


# ── routes ───────────────────────────────────────────────────────────────────
@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "module": "jitsi"}


@app.get("/status")
async def status(_: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Served from the warm cache; falls back to a live call only when nothing
    has been cached yet (first request after a cold install)."""
    cached = _status_cache.get("data")
    if cached is not None:
        return cached
    return await asyncio.to_thread(_refresh_status)


@app.get("/stats")
async def stats(_: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Live colibri counters. NOT cached: conference and participant counts are
    what an operator watches while a call is happening, and a 60 s-old value
    would be worse than useless there. The call is a single HTTP GET to the
    bridge on the LXC bridge network — cheap enough to serve live."""
    return await asyncio.to_thread(lambda: _ctl_json("stats", timeout=15))


@app.post("/control")
async def control(req: ControlRequest, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    if req.action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="action must be start|stop|restart")
    # Container lifecycle is slow (a stop waits for four services to shut down),
    # so it gets a longer budget than the default ctl timeout.
    return await asyncio.to_thread(lambda: _ctl_json(req.action, timeout=120))


@app.post("/service/restart")
async def service_restart(req: ServiceRequest,
                          _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Restart ONE Jitsi service without cycling the container — a container
    restart would drop every conference in progress to fix one daemon."""
    if req.unit not in KNOWN_UNITS:
        raise HTTPException(status_code=400,
                            detail=f"unit must be one of {', '.join(KNOWN_UNITS)}")
    return await asyncio.to_thread(
        lambda: _ctl_json("service-restart", req.unit, timeout=60))


@app.post("/public-ip")
async def set_public_ip(req: PublicIPRequest,
                        _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """The address the videobridge advertises to peers. Behind two NATs it
    cannot discover this alone; a wrong value produces the characteristic
    failure where the conference forms and then carries no media.

    Only emptiness is checked here. The address format is the ctl's rule, and
    stating it in two places is how the two drift apart."""
    if not req.address.strip():
        raise HTTPException(status_code=400, detail="address is required")
    return await asyncio.to_thread(
        lambda: _ctl_json("set-public-ip", req.address.strip(), timeout=60))


@app.get("/logs")
async def logs(unit: str = "jitsi-videobridge2", lines: int = 50,
               _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    if unit not in KNOWN_UNITS:
        raise HTTPException(status_code=400,
                            detail=f"unit must be one of {', '.join(KNOWN_UNITS)}")
    lines = max(1, min(int(lines), 500))
    rc, out, err = await asyncio.to_thread(
        lambda: _run_ctl("logs", unit, str(lines), timeout=30))
    if rc != 0:
        raise HTTPException(status_code=500, detail=(err or out).strip()[:500])
    return {"unit": unit, "lines": out.splitlines()}
