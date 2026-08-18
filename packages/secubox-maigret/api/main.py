# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox Maigret API — username/identity OSINT driven through a sandboxed LXC.

Every handler is plain `def` (FastAPI threadpools it) — the module is mounted
in-process by the aggregator, so an async handler running subprocess would
freeze the shared loop. Container ops go through `sudo -n maigretctl`.

Maigret lookups are PASSIVE (account discovery only, no active probing of the
target), so there is no active-scan gating — but every lookup is still JWT-gated
and written to the append-only audit log.
"""
import os
import re as _re
import json
import time
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Maigret", version="1.0.0")
config = get_config("maigret")

CTL = "/usr/sbin/maigretctl"
CONTAINER_IP = config.get("lxc_ip", "10.100.0.42")
DATA_DIR = Path("/var/lib/secubox/maigret")
LOOKUPS_DIR = DATA_DIR / "lookups"
AUDIT_LOG = Path("/var/log/secubox/audit.log")
LOOKUPS_DIR.mkdir(parents=True, exist_ok=True)

_USERNAME_RE = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ID_RE = _re.compile(r"^[a-f0-9]{8}$")


def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timed out"
    except Exception as e:  # pragma: no cover
        return False, "", str(e)


def ctl(subcmd, timeout=60, stdin=None):
    """`sudo -n maigretctl <subcmd...>` — the only privileged path. Fail-safe."""
    cmd = ["sudo", "-n", CTL, *subcmd]
    if stdin is None:
        return run_cmd(cmd, timeout)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except Exception as e:  # pragma: no cover
        return False, "", str(e)


def _valid_username(u): return bool(u) and bool(_USERNAME_RE.fullmatch(u))
def _valid_id(i): return bool(i) and bool(_ID_RE.fullmatch(i))


# ---- single-flight, stale-while-revalidate cache (ported from openclaw) ----
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
            threading.Thread(target=_bg, name=f"mg-cache-{key}", daemon=True).start()
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
                "tools": {"maigret": False}}
    try:
        return json.loads(out)
    except Exception:
        return {"running": False, "installed": False, "ip": CONTAINER_IP, "tools": {}}

def lxc_running() -> bool:
    return bool(_ctl_status().get("running"))

def _require_installed():
    if not _ctl_status().get("installed"):
        raise HTTPException(409, "Maigret container is not installed")


@app.get("/health")
def health():
    return {"status": "ok", "module": "maigret"}

@app.get("/status")
def status():
    return _cached("status", 15.0, _compute_status)

def _compute_status():
    s = _ctl_status()
    return {"module": "maigret", "enabled": config.get("enabled", True),
            "running": s.get("running", False), "installed": s.get("installed", False),
            "ip": s.get("ip", CONTAINER_IP), "tools": s.get("tools", {}),
            "total_lookups": len(list(LOOKUPS_DIR.glob("*.json")))}


# ============================================================================
# Lookup API — async-job model. Every handler is plain `def`; the worker is a
# fully-detached subprocess (`sudo -n maigretctl lookup ...`) started via
# start_new_session=True so it never blocks the aggregator's shared loop.
# ============================================================================

class LookupReq(BaseModel):
    username: str


def _new_id():
    return os.urandom(4).hex()

def _spawn_worker(username: str, lookup_id: str):
    """Detached — runs entirely off the aggregator. maigretctl does the work
    and writes lookups/<id>.json. We only record 'pending' first."""
    rec = {"id": lookup_id, "username": username, "status": "pending",
           "started_at": datetime.now(timezone.utc).isoformat(), "results": None, "error": None}
    (LOOKUPS_DIR / f"{lookup_id}.json").write_text(json.dumps(rec))
    subprocess.Popen(["sudo", "-n", CTL, "lookup", username, lookup_id],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, start_new_session=True)

def _audit(operator, username, lookup_id, action="lookup"):
    # Append-only — never truncate. `operator` = JWT sub (WHO), `action` = WHAT.
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                "module": "maigret", "action": action,
                                "operator": operator,
                                "username": username, "lookup_id": lookup_id}) + "\n")
    except Exception:  # pragma: no cover - audit must never break a lookup
        pass

def _pending_count() -> int:
    """How many lookups are still running. Each maigret run scans 3000+ sites
    for minutes; on the shared appliance we cap concurrency so a loop of POSTs
    can't saturate CPU/network (the conf's rate_limit_per_min intent, enforced)."""
    n = 0
    for f in LOOKUPS_DIR.glob("*.json"):
        try:
            if json.loads(f.read_text()).get("status") == "pending":
                n += 1
        except Exception:
            pass
    return n

MAX_CONCURRENT_LOOKUPS = int(config.get("max_concurrent_lookups", 3))

@app.post("/lookup", dependencies=[Depends(require_jwt)])
def start_lookup(req: LookupReq, claims: dict = Depends(require_jwt)):
    _require_installed()
    if not _valid_username(req.username):
        raise HTTPException(400, "invalid username")
    if _pending_count() >= MAX_CONCURRENT_LOOKUPS:
        raise HTTPException(429, f"too many lookups running (max {MAX_CONCURRENT_LOOKUPS})")
    lookup_id = _new_id()
    _audit(claims.get("sub", "?"), req.username, lookup_id, action="lookup")
    _spawn_worker(req.username, lookup_id)
    return {"status": "started", "lookup_id": lookup_id, "username": req.username}

@app.get("/lookups", dependencies=[Depends(require_jwt)])
def list_lookups():
    out = []
    for f in sorted(LOOKUPS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:200]:
        try: out.append(json.loads(f.read_text()))
        except Exception: pass
    return {"lookups": out}

@app.get("/lookup/{lookup_id}", dependencies=[Depends(require_jwt)])
def get_lookup(lookup_id: str):
    if not _valid_id(lookup_id):
        raise HTTPException(400, "invalid lookup id")
    f = LOOKUPS_DIR / f"{lookup_id}.json"
    if not f.exists():
        raise HTTPException(404, "not found")
    return json.loads(f.read_text())

@app.get("/lookup/{lookup_id}/report.pdf", dependencies=[Depends(require_jwt)])
def lookup_report(lookup_id: str):
    """Render a completed lookup into a styled, SecuBox-branded PDF dossier.
    Plain `def` → FastAPI threadpools it, so the (sync) fpdf render never blocks
    the shared aggregator loop."""
    if not _valid_id(lookup_id):
        raise HTTPException(400, "invalid lookup id")
    f = LOOKUPS_DIR / f"{lookup_id}.json"
    if not f.exists():
        raise HTTPException(404, "not found")
    record = json.loads(f.read_text())
    from . import report as _report
    try:
        pdf = _report.build_pdf(record)
    except Exception as e:  # noqa: BLE001 — never 500 the panel over a render glitch
        raise HTTPException(500, f"report render failed: {e}")
    safe = _re.sub(r"[^A-Za-z0-9._-]", "_", str(record.get("username", "report")))[:40] or "report"
    from fastapi.responses import Response
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="maigret-{safe}.pdf"'})

@app.delete("/lookup/{lookup_id}", dependencies=[Depends(require_jwt)])
def delete_lookup(lookup_id: str, claims: dict = Depends(require_jwt)):
    if not _valid_id(lookup_id):
        raise HTTPException(400, "invalid lookup id")
    f = LOOKUPS_DIR / f"{lookup_id}.json"
    if f.exists(): f.unlink()
    _audit(claims.get("sub", "?"), "-", lookup_id, action="delete")
    return {"status": "deleted", "lookup_id": lookup_id}

@app.post("/install", dependencies=[Depends(require_jwt)])
def install(claims: dict = Depends(require_jwt)):
    """Build the sandbox container (debootstrap + maigret) in the background.
    Detached like a lookup worker — never runs on the request path."""
    if _ctl_status().get("installed"):
        raise HTTPException(400, "already installed")
    _audit(claims.get("sub", "?"), "-", "-", action="install")
    subprocess.Popen(["sudo", "-n", CTL, "install"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, start_new_session=True)
    _invalidate_stats()
    return {"status": "installing"}
