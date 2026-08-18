# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox SpiderFoot API — LXC lifecycle + status probe for the SpiderFoot
OSINT automation engine.

SpiderFoot ships its OWN web UI + REST API (bound to the container LAN IP), so
this module does NOT wrap scans: scans are driven inside SpiderFoot's own UI,
reverse-proxied behind the SecuBox WAF/auth front. This API only exposes the
container LIFECYCLE (install / start / stop / restart-ui) and a status probe.

Every handler is plain `def` (FastAPI threadpools it) — the module is mounted
in-process by the aggregator, so an async handler running subprocess would
freeze the shared loop. Container ops go through `sudo -n spiderfootctl`; the
install worker is fully detached (start_new_session=True) so nothing blocks the
aggregator's event loop.
"""
import json
import time
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox SpiderFoot", version="1.0.0")
config = get_config("spiderfoot")

CTL = "/usr/sbin/spiderfootctl"
CONTAINER_IP = config.get("lxc_ip", "10.100.0.43")
SF_PORT = int(config.get("sf_port", 5001))
DATA_DIR = Path("/var/lib/secubox/spiderfoot")
AUDIT_LOG = Path("/var/log/secubox/audit.log")
DATA_DIR.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timed out"
    except Exception as e:  # pragma: no cover
        return False, "", str(e)


def ctl(subcmd, timeout=60):
    """`sudo -n spiderfootctl <subcmd...>` — the only privileged path. Fail-safe."""
    return run_cmd(["sudo", "-n", CTL, *subcmd], timeout)


# ---- single-flight, stale-while-revalidate cache (ported from maigret) ----
_STATS_CACHE: dict = {}
_CACHE_LOCKS: dict = {}
_CACHE_LOCKS_GUARD = threading.Lock()

def _cache_lock(key):
    with _CACHE_LOCKS_GUARD:
        return _CACHE_LOCKS.setdefault(key, threading.Lock())

def _cached(key, ttl, producer):
    now = time.monotonic(); hit = _STATS_CACHE.get(key)
    if hit and (now - hit[0]) < ttl:
        return hit[1]
    lock = _cache_lock(key)
    if hit is not None:
        if lock.acquire(blocking=False):
            def _bg():
                try: _STATS_CACHE[key] = (time.monotonic(), producer())
                except Exception: pass
                finally: lock.release()
            threading.Thread(target=_bg, name=f"sf-cache-{key}", daemon=True).start()
        return hit[1]
    with lock:
        hit = _STATS_CACHE.get(key)
        if hit and (time.monotonic() - hit[0]) < ttl:
            return hit[1]
        val = producer(); _STATS_CACHE[key] = (time.monotonic(), val); return val

def _invalidate_stats(): _STATS_CACHE.clear()


def _ctl_status():
    ok, out, _ = ctl(["status", "--json"], timeout=25)
    if not ok:
        return {"running": False, "installed": False, "ip": CONTAINER_IP,
                "port": SF_PORT, "ui_up": False}
    try:
        return json.loads(out)
    except Exception:
        return {"running": False, "installed": False, "ip": CONTAINER_IP,
                "port": SF_PORT, "ui_up": False}


def _audit(operator, action):
    # Append-only — never truncate. `operator` = JWT sub (WHO), `action` = WHAT.
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                "module": "spiderfoot", "action": action,
                                "operator": operator}) + "\n")
    except Exception:  # pragma: no cover - audit must never break the action
        pass


@app.get("/health")
def health():
    return {"status": "ok", "module": "spiderfoot"}


@app.get("/status")
def status():
    return _cached("status", 15.0, _compute_status)

def _compute_status():
    s = _ctl_status()
    return {"module": "spiderfoot", "enabled": config.get("enabled", True),
            "running": s.get("running", False), "installed": s.get("installed", False),
            "ip": s.get("ip", CONTAINER_IP), "port": s.get("port", SF_PORT),
            "ui_up": s.get("ui_up", False)}


# ============================================================================
# Lifecycle API — every mutating endpoint is JWT-gated and audited. Install is
# a fully-detached worker (start_new_session=True) so the debootstrap + git
# clone + pip install never runs on the request path or blocks the aggregator.
# start/stop/restart-ui are short bounded `ctl()` calls.
# ============================================================================

@app.post("/install", dependencies=[Depends(require_jwt)])
def install(claims: dict = Depends(require_jwt)):
    """Build the sandbox container (debootstrap + SpiderFoot) in the background.
    Detached — never runs on the request path."""
    if _ctl_status().get("installed"):
        raise HTTPException(400, "already installed")
    _audit(claims.get("sub", "?"), "install")
    subprocess.Popen(["sudo", "-n", CTL, "install"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, start_new_session=True)
    _invalidate_stats()
    return {"status": "installing"}


@app.post("/start", dependencies=[Depends(require_jwt)])
def start(claims: dict = Depends(require_jwt)):
    _audit(claims.get("sub", "?"), "start")
    ok, _out, errmsg = ctl(["start"], timeout=30)
    _invalidate_stats()
    if not ok:
        raise HTTPException(500, errmsg or "failed to start container")
    return {"status": "started"}


@app.post("/stop", dependencies=[Depends(require_jwt)])
def stop(claims: dict = Depends(require_jwt)):
    _audit(claims.get("sub", "?"), "stop")
    ok, _out, errmsg = ctl(["stop"], timeout=30)
    _invalidate_stats()
    if not ok:
        raise HTTPException(500, errmsg or "failed to stop container")
    return {"status": "stopped"}


@app.post("/restart-ui", dependencies=[Depends(require_jwt)])
def restart_ui(claims: dict = Depends(require_jwt)):
    _audit(claims.get("sub", "?"), "restart-ui")
    ok, _out, errmsg = ctl(["restart-ui"], timeout=30)
    _invalidate_stats()
    if not ok:
        raise HTTPException(500, errmsg or "failed to restart SpiderFoot UI")
    return {"status": "restarted"}
