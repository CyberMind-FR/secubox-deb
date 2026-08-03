# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-jellyfin — host control plane API (LXC-native).
CyberMind — https://cybermind.fr

FastAPI on /run/secubox/jellyfin.sock, proxied by nginx at /api/v1/jellyfin/.
DEDICATED socket (secubox-jellyfin.service) — NOT the aggregator: this API
(a) sudo's the root `jellyfinctl` actuator (needs NoNewPrivileges=no, which the
aggregator does not grant) and (b) runs a background /status cache refresher on
startup (mounted sub-apps never get a lifespan on the aggregator loop). See the
`WebUI-delegates-to-confined-ctl` rule in MODULE-COMPLIANCE.md: this API does
NO privileged work itself — every state change is delegated to `jellyfinctl`,
the single audited root surface.

Endpoints (all JWT-gated except /health):
  GET  /health          public liveness ({status, module})
  GET  /status          jellyfinctl status — 60 s double-cached (bg refresh)
  GET  /partners        jellyfinctl partner list
  GET  /library/status  jellyfinctl library status
  POST /partner/wire    {name?, all?}  → jellyfinctl partner wire <name|--all>
  POST /partner/unwire  {name}         → jellyfinctl partner unwire <name>
  POST /control         {action}       → jellyfinctl start|stop|restart
  POST /library/scan    jellyfinctl library scan
  GET  /check-upgrade   jellyfinctl check-upgrade
  POST /upgrade         jellyfinctl upgrade
  GET  /playback        jellyfinctl playback status
  POST /playback/apply  jellyfinctl playback apply
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from secubox_core.auth import require_jwt

VERSION = "2.0.0"

# The single privileged surface. The panel/API is unprivileged (User=secubox);
# every actuation is `sudo -n /usr/sbin/jellyfinctl <verb>` (scoped sudoers,
# see debian/secubox-jellyfin.sudoers). jellyfinctl emits a JSON payload on
# stdout for each verb (the machine-readable contract this API parses).
CTL = "/usr/sbin/jellyfinctl"

# Double-caching (CLAUDE.md § Performance Patterns): /status is refreshed in the
# background every 60 s and mirrored to a JSON file so the panel never blocks on
# the (LXC-touching) ctl call and survives an API restart with a warm value.
CACHE_DIR = Path("/var/cache/secubox/jellyfin")
STATUS_CACHE_FILE = CACHE_DIR / "status.json"
STATUS_TTL = 60.0

log = logging.getLogger("secubox-jellyfin")

app = FastAPI(
    title="SecuBox Jellyfin",
    version=VERSION,
    root_path="/api/v1/jellyfin",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# In-memory status cache, kept warm by the background refresher.
_status_cache: Dict[str, Any] = {"data": None, "ts": 0.0}


# ── ctl runners ──────────────────────────────────────────────────────────────
def _run_ctl(*args: str, timeout: int = 30):
    """Low-level: `sudo -n jellyfinctl <args>` → (returncode, stdout, stderr).

    Never raises — a missing/slow/erroring ctl must degrade the panel, not
    crash the request handler."""
    try:
        p = subprocess.run(
            ["sudo", "-n", CTL, *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"jellyfinctl {' '.join(args)} timed out after {timeout}s"
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", f"jellyfinctl invocation failed: {exc}"


def _ctl_json(*args: str, timeout: int = 30) -> Dict[str, Any]:
    """Run the ctl and return its parsed JSON stdout.

    Raises HTTPException(500) with the ctl's stderr on any failure (non-zero
    exit, invocation error, or non-JSON output)."""
    rc, out, err = _run_ctl(*args, timeout=timeout)
    if rc != 0:
        detail = (err or out or f"jellyfinctl exited {rc}").strip()[:500]
        raise HTTPException(status_code=500, detail=detail)
    out = out.strip()
    if not out:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail=f"jellyfinctl emitted non-JSON: {out[:300]!r}",
        )


# ── /status double-cache ─────────────────────────────────────────────────────
def _refresh_status() -> Dict[str, Any]:
    """Blocking status fetch (runs off-loop via asyncio.to_thread). Updates the
    in-memory cache and mirrors to CACHE_DIR. Raises on ctl failure."""
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
    """Background task: refresh the status cache every STATUS_TTL seconds."""
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
    # Warm the in-memory cache from the on-disk mirror so the first /status
    # after a restart is served instantly instead of blocking on the ctl.
    if _status_cache["data"] is None and STATUS_CACHE_FILE.is_file():
        try:
            _status_cache["data"] = json.loads(STATUS_CACHE_FILE.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    asyncio.create_task(_status_refresher())


# ── request bodies ───────────────────────────────────────────────────────────
class WireBody(BaseModel):
    name: Optional[str] = None
    all: bool = False


class UnwireBody(BaseModel):
    name: str


class ControlBody(BaseModel):
    action: str


_CONTROL_ACTIONS = {"start", "stop", "restart"}


# ── endpoints ────────────────────────────────────────────────────────────────
@app.get("/health")
async def health() -> Dict[str, str]:
    """Public liveness — no auth (used by the sidebar / watchdog)."""
    return {"status": "ok", "module": "jellyfin"}


@app.get("/status", dependencies=[Depends(require_jwt)])
async def status() -> Dict[str, Any]:
    """LXC state + jellyfin health + libraries + sessions, 60 s double-cached.

    Served from the in-memory cache kept warm by the background refresher; on a
    cold cache we fetch once off-loop so we never block the event loop."""
    if _status_cache["data"] is not None:
        return _status_cache["data"]
    return await asyncio.to_thread(_refresh_status)


@app.get("/partners", dependencies=[Depends(require_jwt)])
def partners() -> Dict[str, Any]:
    """Sibling media services + whether each is present/wired as a library."""
    return _ctl_json("partner", "list")


@app.get("/library/status", dependencies=[Depends(require_jwt)])
def library_status() -> Dict[str, Any]:
    """Jellyfin library summary (virtual folders + last scan)."""
    return _ctl_json("library", "status")


@app.post("/partner/wire", dependencies=[Depends(require_jwt)])
def partner_wire(body: WireBody) -> Dict[str, Any]:
    """Wire one partner (RO bind + Jellyfin virtual folder) or every present
    partner with `all: true`. Wiring may take a while (bind + scan)."""
    if body.all:
        return _ctl_json("partner", "wire", "--all", timeout=180)
    if not body.name:
        raise HTTPException(status_code=400, detail="'name' or 'all' is required")
    return _ctl_json("partner", "wire", body.name, timeout=180)


@app.post("/partner/unwire", dependencies=[Depends(require_jwt)])
def partner_unwire(body: UnwireBody) -> Dict[str, Any]:
    """Remove a partner's virtual folder + RO bind."""
    if not body.name:
        raise HTTPException(status_code=400, detail="'name' is required")
    return _ctl_json("partner", "unwire", body.name, timeout=120)


@app.post("/control", dependencies=[Depends(require_jwt)])
def control(body: ControlBody) -> Dict[str, Any]:
    """Start / stop / restart the Jellyfin LXC."""
    if body.action not in _CONTROL_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"action must be one of {sorted(_CONTROL_ACTIONS)}",
        )
    return _ctl_json(body.action, timeout=120)


@app.post("/library/scan", dependencies=[Depends(require_jwt)])
def library_scan() -> Dict[str, Any]:
    """Trigger a Jellyfin library scan (runs in the background inside the LXC)."""
    return _ctl_json("library", "scan", timeout=60)


@app.get("/check-upgrade", dependencies=[Depends(require_jwt)])
def check_upgrade() -> Dict[str, Any]:
    """Compare the installed Jellyfin version against the latest available."""
    return _ctl_json("check-upgrade", timeout=60)


@app.post("/upgrade", dependencies=[Depends(require_jwt)])
def upgrade() -> Dict[str, Any]:
    """Upgrade Jellyfin inside the LXC to the latest pinned release."""
    return _ctl_json("upgrade", timeout=600)


@app.get("/playback", dependencies=[Depends(require_jwt)])
def playback_status() -> Dict[str, Any]:
    """Per-user transcoding/remux policy vs. the declared [playback] config.

    Disabling transcoding is a real tradeoff (a file the client cannot
    decode natively will refuse to play instead of degrading through a
    software re-encode) — see jellyfin.toml / README for the rationale."""
    return _ctl_json("playback", "status", timeout=20)


@app.post("/playback/apply", dependencies=[Depends(require_jwt)])
def playback_apply() -> Dict[str, Any]:
    """Push the declared [playback] policy onto every current Jellyfin user.

    A user created after the fact keeps Jellyfin's own default (transcoding
    enabled) until this runs — also swept periodically by the
    secubox-jellyfin-playback-policy timer."""
    return _ctl_json("playback", "apply", timeout=60)
