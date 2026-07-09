"""SecuBox OpenClaw API — OSINT + active scanner driven through a sandboxed LXC.

Every handler is plain `def` (FastAPI threadpools it) — the module is mounted
in-process by the aggregator, so an async handler running subprocess would
freeze the shared loop. Container ops go through `sudo -n openclawctl`.
"""
import os
import re as _re
import json
import time
import ipaddress
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox OpenClaw", version="2.0.0")
config = get_config("openclaw")

CTL = "/usr/sbin/openclawctl"
CONTAINER_IP = config.get("lxc_ip", "10.100.0.41")
DATA_DIR = Path("/var/lib/secubox/openclaw")
SCANS_DIR = DATA_DIR / "scans"
AUDIT_LOG = Path("/var/log/secubox/audit.log")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

_UID_RE = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]*$")
_ID_RE = _re.compile(r"^[a-f0-9]{8}$")
OWNED = [d.lower().lstrip(".") for d in config.get("owned_domains", ["gk2.secubox.in"])]


def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timed out"
    except Exception as e:  # pragma: no cover
        return False, "", str(e)


def ctl(subcmd, timeout=60, stdin=None):
    """`sudo -n openclawctl <subcmd...>` — the only privileged path. Fail-safe."""
    cmd = ["sudo", "-n", CTL, *subcmd]
    if stdin is None:
        return run_cmd(cmd, timeout)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except Exception as e:  # pragma: no cover
        return False, "", str(e)


def _valid_target(t): return bool(t) and bool(_UID_RE.fullmatch(t))
def _valid_scanid(i): return bool(i) and bool(_ID_RE.fullmatch(i))


def _is_local_or_owned(target: str) -> bool:
    """True if target is RFC1918/loopback/link-local (IP or CIDR) or a box-owned
    domain suffix. Used to gate active scans without an explicit authorization."""
    t = target.strip().lower()
    host = t.split("/")[0].split("@")[-1]
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(t, strict=False)
        return net.is_private or net.is_loopback
    except ValueError:
        pass
    return any(host == d or host.endswith("." + d) for d in OWNED)


# ---- single-flight, stale-while-revalidate cache (ported from nextcloud) ----
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
            threading.Thread(target=_bg, name=f"oc-cache-{key}", daemon=True).start()
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
                "tools": {"nmap": False, "dig": False, "whois": False, "curl": False}}
    try:
        return json.loads(out)
    except Exception:
        return {"running": False, "installed": False, "ip": CONTAINER_IP, "tools": {}}

def lxc_running() -> bool:
    return bool(_ctl_status().get("running"))

def _require_installed():
    if not _ctl_status().get("installed"):
        raise HTTPException(409, "OpenClaw container is not installed")


@app.get("/health")
def health():
    return {"status": "ok", "module": "openclaw"}

@app.get("/status")
def status():
    return _cached("status", 15.0, _compute_status)

def _compute_status():
    s = _ctl_status()
    return {"module": "openclaw", "enabled": config.get("enabled", True),
            "running": s.get("running", False), "installed": s.get("installed", False),
            "ip": s.get("ip", CONTAINER_IP), "tools": s.get("tools", {}),
            "total_scans": len(list(SCANS_DIR.glob("*.json")))}

@app.get("/config", dependencies=[Depends(require_jwt)])
def get_config_endpoint():
    return {"enabled": config.get("enabled", True), "owned_domains": OWNED,
            "integrations": {k: bool(config.get(k)) for k in
                             ("shodan_api_key", "censys_api_id", "virustotal_api_key")}}



# ============================================================================
# Scan API — async-job model. Every handler is plain `def`; the worker is a
# fully-detached subprocess (`sudo -n openclawctl scan ...`) started via
# start_new_session=True so it never blocks the aggregator's shared loop.
# ============================================================================

class ScanReq(BaseModel):
    target: str
    authorized: bool = False

# domain/email = passive (unrestricted); ip/ports = active (policy-gated)
_ACTIVE_TYPES = {"ip", "ports"}

def _new_id():
    return os.urandom(4).hex()

def _spawn_worker(scan_type: str, target: str, scan_id: str):
    """Detached — runs entirely off the aggregator. openclawctl does the work
    and writes scans/<id>.json. We only record 'pending' first."""
    rec = {"id": scan_id, "type": scan_type, "target": target, "status": "pending",
           "started_at": datetime.now(timezone.utc).isoformat(), "results": None, "error": None}
    (SCANS_DIR / f"{scan_id}.json").write_text(json.dumps(rec))
    subprocess.Popen(["sudo", "-n", CTL, "scan", scan_type, target, scan_id],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, start_new_session=True)

def _audit(operator, scan_type, target, authorized, scan_id, action="scan"):
    # Append-only — never truncate. `operator` = JWT sub (WHO), `action` = WHAT.
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                "module": "openclaw", "action": action,
                                "operator": operator,
                                "type": scan_type, "target": target,
                                "authorized": authorized, "scan_id": scan_id}) + "\n")
    except Exception:  # pragma: no cover - audit must never break a scan
        pass

def _start_scan(scan_type, req: ScanReq, operator: str):
    _require_installed()
    if not _valid_target(req.target):
        raise HTTPException(400, "invalid target")
    if scan_type in _ACTIVE_TYPES and not _is_local_or_owned(req.target) and not req.authorized:
        raise HTTPException(409, "external active scan requires authorized=true")
    scan_id = _new_id()
    if scan_type in _ACTIVE_TYPES:
        _audit(operator, scan_type, req.target, req.authorized, scan_id, action="scan")
    _spawn_worker(scan_type, req.target, scan_id)
    return {"status": "started", "scan_id": scan_id, "type": scan_type, "target": req.target}

@app.post("/scan/domain", dependencies=[Depends(require_jwt)])
def scan_domain(req: ScanReq, claims: dict = Depends(require_jwt)):
    return _start_scan("domain", req, claims.get("sub", "?"))

@app.post("/scan/ip", dependencies=[Depends(require_jwt)])
def scan_ip(req: ScanReq, claims: dict = Depends(require_jwt)):
    return _start_scan("ip", req, claims.get("sub", "?"))

@app.post("/scan/email", dependencies=[Depends(require_jwt)])
def scan_email(req: ScanReq, claims: dict = Depends(require_jwt)):
    return _start_scan("email", req, claims.get("sub", "?"))

@app.get("/scans", dependencies=[Depends(require_jwt)])
def list_scans():
    out = []
    for f in sorted(SCANS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:200]:
        try: out.append(json.loads(f.read_text()))
        except Exception: pass
    return {"scans": out}

@app.get("/scan/{scan_id}", dependencies=[Depends(require_jwt)])
def get_scan(scan_id: str):
    if not _valid_scanid(scan_id):
        raise HTTPException(400, "invalid scan id")
    f = SCANS_DIR / f"{scan_id}.json"
    if not f.exists():
        raise HTTPException(404, "not found")
    return json.loads(f.read_text())

@app.delete("/scan/{scan_id}", dependencies=[Depends(require_jwt)])
def delete_scan(scan_id: str):
    if not _valid_scanid(scan_id):
        raise HTTPException(400, "invalid scan id")
    f = SCANS_DIR / f"{scan_id}.json"
    if f.exists(): f.unlink()
    return {"status": "deleted", "scan_id": scan_id}

def _sync_lookup(scan_type, target):
    _require_installed()
    if not _valid_target(target):
        raise HTTPException(400, "invalid target")
    # Per-request id: two concurrent (threadpooled) lookups must not race on one
    # file and read back each other's result. Transient — cleaned up, never
    # persisted in /scans.
    tmp_id = _new_id()
    ctl(["scan", scan_type, target, tmp_id], timeout=45)
    f = SCANS_DIR / f"{tmp_id}.json"
    try:
        if f.exists():
            data = json.loads(f.read_text())
            return data
        return {"status": "failed", "results": {"raw": ""}}
    finally:
        try: f.unlink()
        except OSError: pass

# Passive OSINT quick-lookups — unrestricted (no active probing).
@app.get("/dns/{domain}", dependencies=[Depends(require_jwt)])
def dns_lookup(domain: str): return _sync_lookup("dns", domain)

@app.get("/whois/{target}", dependencies=[Depends(require_jwt)])
def whois_lookup(target: str): return _sync_lookup("whois", target)

@app.get("/certs/{domain}", dependencies=[Depends(require_jwt)])
def certs_lookup(domain: str): return _sync_lookup("certs", domain)

# Active quick-lookup — `ports` is a real nmap probe, so it is policy-gated and
# audited. External targets must go through the gated POST /scan/ip (authorized=true).
@app.get("/ports/{ip}", dependencies=[Depends(require_jwt)])
def ports_lookup(ip: str, claims: dict = Depends(require_jwt)):
    _require_installed()
    if not _valid_target(ip):
        raise HTTPException(400, "invalid target")
    if not _is_local_or_owned(ip):
        raise HTTPException(409, "external active port scan requires POST /scan/ip with authorized=true")
    _audit(claims.get("sub", "?"), "ports", ip, False, "quicklook", action="scan")
    return _sync_lookup("ports", ip)

@app.post("/install", dependencies=[Depends(require_jwt)])
def install():
    """Build the sandbox container (debootstrap + toolchain) in the background.
    Detached like a scan worker — never runs on the request path."""
    if _ctl_status().get("installed"):
        raise HTTPException(400, "already installed")
    subprocess.Popen(["sudo", "-n", CTL, "install"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, start_new_session=True)
    _invalidate_stats()
    return {"status": "installing"}
