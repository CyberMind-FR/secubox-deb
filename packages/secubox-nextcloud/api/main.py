"""SecuBox Nextcloud API - File Sync & Cloud Storage with LXC"""
import re as _re
import subprocess
import os
import time
import threading
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Nextcloud")
config = get_config("nextcloud")

LXC_NAME = config.get("container_name", "nextcloud")
LXC_PATH = Path(config.get("lxc_path", "/srv/lxc"))
DATA_PATH = Path(config.get("data_path", "/srv/nextcloud"))
LXC_ROOTFS = LXC_PATH / LXC_NAME / "rootfs"


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


CTL = "/usr/sbin/nextcloudctl"
CONTAINER_IP = config.get("container_ip", "10.100.0.21")
HTTP_PORT = int(config.get("http_port", 8080) or 8080)
DOMAIN = config.get("domain", "nc.gk2.secubox.in")


def ctl(subcmd: list, timeout: int = 60, stdin: str = None) -> tuple:
    """Run `sudo -n nextcloudctl <subcmd...>`. The ONLY privileged path: the
    aggregator runs as `secubox` (NNP=no) with a NOPASSWD sudoers entry for
    nextcloudctl. Fail-safe: returns (ok, out, err), never raises."""
    cmd = ["sudo", "-n", CTL, *subcmd]
    if stdin is None:
        return run_cmd(cmd, timeout)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, input=stdin)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timed out"
    except Exception as e:  # pragma: no cover - defensive
        return False, "", str(e)


_STATS_CACHE: dict = {}
_CACHE_LOCKS: dict = {}
_CACHE_LOCKS_GUARD = threading.Lock()


def _cache_lock(key: str) -> threading.Lock:
    with _CACHE_LOCKS_GUARD:
        return _CACHE_LOCKS.setdefault(key, threading.Lock())


def _cached(key: str, ttl: float, producer):
    """Single-flight, serve-stale TTL cache for the expensive auto-polled read
    endpoints (/status, /storage). Each producer does several seconds of
    lxc-attach/occ; the dashboard auto-refreshes them and multiple tabs poll in
    parallel. A plain TTL cache does NOT help here: every poll arriving during
    the ~6s compute window misses (the cache only fills when the producer
    returns) and they ALL spawn the helper at once → thundering herd →
    congestion collapse on a memory-tight board (observed: load avg 9+, status
    timing out).

    So: (1) fresh cache → return it; (2) stale/empty but another thread is
    already refreshing → return the last value immediately (serve-stale,
    non-blocking) so concurrent polls never pile on; (3) only ONE thread at a
    time runs the producer (single-flight), double-checking under the lock.
    Stale-by-≤ttl+one-compute is fine for dashboard stats (CLAUDE.md
    double-caching). Handlers are plain def (threadpool) → threading.Lock."""
    now = time.monotonic()
    hit = _STATS_CACHE.get(key)
    if hit and (now - hit[0]) < ttl:
        return hit[1]                       # fresh → instant

    lock = _cache_lock(key)
    if hit is not None:
        # Expired but usable: serve the stale value IMMEDIATELY and refresh in a
        # background thread. A dashboard poll never blocks on the ~6s compute
        # after the first load, and single-flight (non-blocking acquire) means
        # only one refresh runs regardless of how many polls arrive.
        if lock.acquire(blocking=False):
            def _bg():
                try:
                    _STATS_CACHE[key] = (time.monotonic(), producer())
                except Exception:           # pragma: no cover - defensive
                    pass
                finally:
                    lock.release()
            threading.Thread(target=_bg, name=f"nc-cache-{key}", daemon=True).start()
        return hit[1]

    # Cold cache (no value yet): block once, single-flight, double-checked.
    with lock:
        hit = _STATS_CACHE.get(key)
        if hit and (time.monotonic() - hit[0]) < ttl:
            return hit[1]
        val = producer()
        _STATS_CACHE[key] = (time.monotonic(), val)
        return val


def _invalidate_stats():
    """Drop cached status/storage after a lifecycle action so the dashboard
    reflects start/stop/restart/user changes immediately, not after the TTL."""
    _STATS_CACHE.clear()


def lxc_running() -> bool:
    """Authoritative container state via the privileged helper."""
    ok, out, _ = ctl(["status", "--json"], timeout=20)
    if not ok:
        return False
    try:
        import json
        return bool(json.loads(out).get("running"))
    except Exception:
        return False


def lxc_installed() -> bool:
    """Check if LXC container exists"""
    config_file = LXC_PATH / LXC_NAME / "config"
    return config_file.exists() and LXC_ROOTFS.exists()


def lxc_attach(command: str, timeout: int = 30) -> tuple:
    """Execute command inside LXC container"""
    cmd = ["lxc-attach", "-n", LXC_NAME, "--", "sh", "-c", command]
    return run_cmd(cmd, timeout)


def occ_cmd(command: str, timeout: int = 60) -> tuple:
    """Run an occ command via the privileged helper's occ passthrough."""
    return ctl(["occ", *command.split()], timeout=timeout)


def container_reachable() -> bool:
    """True if the Nextcloud container is actually serving on its HTTP port.
    Bounded + fail-safe (never raises)."""
    import socket
    try:
        with socket.create_connection((CONTAINER_IP, 80), timeout=1.5):
            return True
    except Exception:
        return False


def public_url() -> str:
    """The real, user-facing base URL (the WAF-fronted vhost), never localhost."""
    u = config.get("public_url")
    if u:
        return u.rstrip("/")
    return f"https://{DOMAIN}"


# #429 injection guards: a Nextcloud uid/quota/backup-name is validated against
# a safe charset BEFORE it ever reaches `ctl()`/argv or a filesystem path,
# mirroring nextcloudctl's own `_valid_uid`/`_valid_quota` (defense in depth,
# not a substitute for it). `.fullmatch` (not `.match`) so a trailing
# newline (which `$` in Python regexes tolerates) can't sneak a valid-looking
# string past the guard.
_UID_RE = _re.compile(r"^[A-Za-z0-9._@-]+$")
_QUOTA_RE = _re.compile(r"^(none|default|[0-9]+(\.[0-9]+)?[KMGT]?B?)$", _re.I)
_BACKUP_RE = _re.compile(r"^[A-Za-z0-9._-]+$")


def _require_running():
    if not lxc_running():
        raise HTTPException(409, "Nextcloud container is not running")


def _valid_uid(uid: str) -> bool:
    return bool(uid) and bool(_UID_RE.fullmatch(uid))


def _valid_backup_name(name: str) -> bool:
    return bool(name) and bool(_BACKUP_RE.fullmatch(name))


class NewUser(BaseModel):
    uid: str
    display_name: str = ""
    password: str


class QuotaReq(BaseModel):
    quota: str


# Public endpoints
@app.get("/status")
def status():
    """Get Nextcloud service status (cached 15s — heavy lxc/occ, auto-polled)."""
    return _cached("status", 15.0, _compute_status)


def _compute_status():
    installed = lxc_installed()
    running = False
    version = ""
    user_count = 0
    ok, out, _ = ctl(["status", "--json"], timeout=20)
    if ok:
        try:
            import json
            s = json.loads(out)
            running = bool(s.get("running"))
            installed = installed or bool(s.get("installed"))
            version = s.get("version", "") or ""
            user_count = int(s.get("user_count", 0) or 0)
        except Exception:
            pass
    reachable = container_reachable() if running else False

    # Get disk usage
    disk_used = "0"
    data_dir = DATA_PATH / "data"
    if data_dir.exists():
        success, out, _ = run_cmd(["du", "-sh", str(data_dir)])
        if success:
            disk_used = out.split()[0]

    return {
        "module": "nextcloud",
        "enabled": config.get("enabled", True),
        "running": running,
        "reachable": reachable,
        "installed": installed,
        "version": version,
        "http_port": HTTP_PORT,
        "data_path": str(DATA_PATH),
        "domain": DOMAIN,
        "user_count": user_count,
        "disk_used": disk_used,
        "web_url": public_url(),
        "ssl_enabled": config.get("ssl_enabled", False),
        "container_name": LXC_NAME,
    }


@app.get("/health")
def health():
    return {"status": "ok", "module": "nextcloud"}


# Protected endpoints
@app.get("/config", dependencies=[Depends(require_jwt)])
def get_config_endpoint():
    """Get Nextcloud configuration"""
    return {
        "enabled": config.get("enabled", True),
        "http_port": config.get("http_port", 8080),
        "data_path": str(DATA_PATH),
        "domain": config.get("domain", "cloud.local"),
        "admin_user": config.get("admin_user", "admin"),
        "memory_limit": config.get("memory_limit", "1G"),
        "upload_max": config.get("upload_max", "512M"),
        "redis_enabled": config.get("redis_enabled", True),
        "ssl_enabled": config.get("ssl_enabled", False),
        "ssl_domain": config.get("ssl_domain", ""),
        "backup_enabled": config.get("backup_enabled", True),
        "backup_keep": config.get("backup_keep", 7),
    }


class ConfigUpdate(BaseModel):
    http_port: Optional[int] = None
    domain: Optional[str] = None
    memory_limit: Optional[str] = None
    upload_max: Optional[str] = None


@app.post("/config", dependencies=[Depends(require_jwt)])
def save_config(update: ConfigUpdate):
    """Save Nextcloud configuration"""
    return {"success": True, "message": "Configuration saved"}


@app.post("/start", dependencies=[Depends(require_jwt)])
def start_service():
    """Start Nextcloud container"""
    if lxc_running():
        raise HTTPException(400, "Service is already running")
    if not lxc_installed():
        raise HTTPException(400, "Container not installed")

    success, _, err = ctl(["start"])
    if success:
        _invalidate_stats()
        return {"success": True, "message": "Service started"}
    raise HTTPException(500, f"Failed to start: {err}")


@app.post("/stop", dependencies=[Depends(require_jwt)])
def stop_service():
    """Stop Nextcloud container"""
    if not lxc_running():
        raise HTTPException(400, "Service is not running")

    success, _, err = ctl(["stop"])
    if success:
        _invalidate_stats()
        return {"success": True, "message": "Service stopped"}
    raise HTTPException(500, f"Failed to stop: {err}")


@app.post("/restart", dependencies=[Depends(require_jwt)])
def restart_service():
    """Restart Nextcloud container. `nextcloudctl restart` does its own
    stop-then-start internally, so a single ctl() call covers it."""
    success, _, err = ctl(["restart"])
    if success:
        _invalidate_stats()
        return {"success": True, "message": "Service restarted"}
    raise HTTPException(500, f"Restart failed: {err}")


@app.post("/install", dependencies=[Depends(require_jwt)])
def install():
    """Install Nextcloud (background). `nextcloudctl install` takes several
    minutes (debootstrap + apt + nextcloud download) so it's detached rather
    than run through the blocking `ctl()` helper -- but it still goes through
    the same `sudo -n nextcloudctl` privileged path (ref #429 I3), never a
    bare non-sudo invocation."""
    if lxc_installed():
        raise HTTPException(400, "Already installed")

    subprocess.Popen(
        ["sudo", "-n", CTL, "install"],
        stdout=open("/var/log/nextcloud-install.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {
        "success": True,
        "message": "Installation started in background",
        "log_file": "/var/log/nextcloud-install.log"
    }


@app.post("/uninstall", dependencies=[Depends(require_jwt)])
def uninstall():
    """Uninstall Nextcloud (preserves data). `nextcloudctl uninstall` prompts
    for a yes/no confirmation on stdin; the API call already gates this
    action behind JWT auth, so the confirmation is answered automatically."""
    success, out, err = ctl(["uninstall"], stdin="yes\n", timeout=120)
    if success:
        return {"success": True, "message": "Uninstalled (data preserved)"}
    raise HTTPException(500, f"Uninstall failed: {err or out}")


@app.post("/update", dependencies=[Depends(require_jwt)])
def update():
    """Update Nextcloud.

    NOTE (ref #429 I3): nextcloudctl has no `update` subcommand (checked the
    full `case "$1" in ... esac` dispatch in sbin/nextcloudctl) so this
    endpoint is left calling the standalone binary directly, unrouted through
    ctl()/sudo, as instructed -- it will keep failing under the unprivileged
    aggregator until a real `nextcloudctl update` arm exists. Not invented
    here."""
    subprocess.Popen(
        ["/usr/sbin/nextcloudctl", "update"],
        stdout=open("/var/log/nextcloud-update.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {"success": True, "message": "Update started in background"}


@app.get("/users", dependencies=[Depends(require_jwt)])
def get_users():
    """List Nextcloud users, detailed (uid/displayname/enabled/quota)."""
    _require_running()
    ok, out, err = ctl(["user", "list"], timeout=30)
    if not ok:
        raise HTTPException(500, f"user list failed: {err}")
    import json
    try:
        data = json.loads(out)
    except Exception:
        data = []
    # `user list` (occ user:list --info) emits a map {uid: {display_name, enabled,
    # quota, last_seen, email, …}}. Older/fallback occ emits a bare {uid: displayname}.
    # Normalise both to the flat rows the dashboard renders.
    if isinstance(data, dict):
        users = []
        for k, v in data.items():
            if isinstance(v, dict):
                users.append({
                    "uid": k,
                    "displayname": v.get("display_name") or v.get("displayname") or k,
                    "enabled": v.get("enabled", True),
                    "quota": v.get("quota") or "",
                    "last_seen": v.get("last_seen", ""),
                    "email": v.get("email", ""),
                })
            else:
                users.append({"uid": k, "displayname": v, "enabled": True, "quota": ""})
    else:
        users = data
    return {"users": users}


@app.post("/user", dependencies=[Depends(require_jwt)])
def create_user(req: NewUser):
    """Create a Nextcloud user. Password travels via stdin only — never argv
    (which would leak it in `ps`)."""
    _require_running()
    if not _valid_uid(req.uid):
        raise HTTPException(400, "invalid uid")
    ok, out, err = ctl(["user", "add", req.uid, req.display_name or req.uid],
                        stdin=req.password + "\n", timeout=60)
    if not ok:
        raise HTTPException(500, f"create failed: {err or out}")
    return {"success": True}


@app.delete("/user/{uid}", dependencies=[Depends(require_jwt)])
def delete_user(uid: str):
    _require_running()
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    ok, _, err = ctl(["user", "del", uid], timeout=60)
    if not ok:
        raise HTTPException(500, f"delete failed: {err}")
    return {"success": True}


@app.post("/user/{uid}/enable", dependencies=[Depends(require_jwt)])
def enable_user(uid: str):
    _require_running()
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    ok, _, err = ctl(["user", "enable", uid])
    if not ok:
        raise HTTPException(500, f"enable failed: {err}")
    return {"success": True}


@app.post("/user/{uid}/disable", dependencies=[Depends(require_jwt)])
def disable_user(uid: str):
    _require_running()
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    ok, _, err = ctl(["user", "disable", uid])
    if not ok:
        raise HTTPException(500, f"disable failed: {err}")
    return {"success": True}


@app.post("/user/{uid}/quota", dependencies=[Depends(require_jwt)])
def set_quota(uid: str, req: QuotaReq):
    _require_running()
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    if not _QUOTA_RE.fullmatch(req.quota or ""):
        raise HTTPException(400, "invalid quota")
    ok, _, err = ctl(["user", "quota", uid, req.quota])
    if not ok:
        raise HTTPException(500, f"quota failed: {err}")
    return {"success": True}


class ResetPassword(BaseModel):
    uid: str
    password: str


@app.post("/user/password", dependencies=[Depends(require_jwt)])
def reset_password(req: ResetPassword):
    """Reset a Nextcloud user's password. Password travels via stdin only —
    never argv/interpolated shell string (ref #429: the old implementation
    built `OC_PASS='{password}'` into a `su -c` command string, leaking the
    password to `ps` and letting an embedded `'` break out of the quoting)."""
    _require_running()
    if not _valid_uid(req.uid):
        raise HTTPException(400, "invalid uid")
    ok, out, err = ctl(["user", "setpass", req.uid],
                        stdin=req.password + "\n", timeout=60)
    if not ok:
        raise HTTPException(500, f"Failed: {err or out}")
    return {"success": True, "message": f"Password reset for {req.uid}"}


@app.get("/storage", dependencies=[Depends(require_jwt)])
def get_storage():
    """Storage usage (cached 30s — heavy in-container du, auto-polled)."""
    return _cached("storage", 30.0, _compute_storage)


def _compute_storage():
    """Get real storage usage from INSIDE the container via the privileged
    helper (the host can't see the unprivileged LXC's data). Fail-safe:
    degrades to zeros on any ctl/parse error, never raises/500s."""
    used = "0"
    total = "0"
    used_pct = 0
    data = "0"

    ok, out, _ = ctl(["storage", "--json"], timeout=30)
    if ok:
        try:
            import json
            s = json.loads(out)
            used = s.get("used", "0") or "0"
            total = s.get("total", "0") or "0"
            used_pct = int(s.get("used_pct", 0) or 0)
            data = s.get("data", "0") or "0"
        except Exception:
            pass

    backup_size = "0"
    backup_dir = DATA_PATH / "backups"
    if backup_dir.exists():
        success, out, _ = run_cmd(["du", "-sh", str(backup_dir)])
        if success:
            backup_size = out.split()[0]

    return {
        "used": used,
        "total": total,
        "used_pct": used_pct,
        "data": data,
        "backup_size": backup_size,
    }


@app.get("/backups", dependencies=[Depends(require_jwt)])
def list_backups():
    """List available backups"""
    backups = []
    backup_dir = DATA_PATH / "backups"

    if backup_dir.exists():
        for f in backup_dir.glob("*-db.sql"):
            name = f.stem.replace("-db", "")
            data_file = backup_dir / f"{name}-data.tar.gz"
            size = "N/A"
            timestamp = 0

            if data_file.exists():
                try:
                    stat = data_file.stat()
                    size = f"{stat.st_size // 1024 // 1024}M"
                except:
                    pass

            try:
                timestamp = int(f.stat().st_mtime)
            except:
                pass

            backups.append({
                "name": name,
                "size": size,
                "timestamp": timestamp
            })

    return {"backups": sorted(backups, key=lambda x: x["timestamp"], reverse=True)}


class BackupRequest(BaseModel):
    name: Optional[str] = None


@app.post("/backup", dependencies=[Depends(require_jwt)])
def create_backup(req: BackupRequest):
    """Create a backup"""
    if req.name and not _valid_backup_name(req.name):
        raise HTTPException(400, "invalid backup name")

    sub = ["backup"]
    if req.name:
        sub.append(req.name)

    success, out, err = ctl(sub, timeout=300)
    if success:
        return {"success": True, "message": "Backup created"}
    raise HTTPException(500, f"Backup failed: {err or out}")


@app.delete("/backup/{name}", dependencies=[Depends(require_jwt)])
def delete_backup(name: str):
    """Delete a backup"""
    if not _valid_backup_name(name):
        raise HTTPException(400, "invalid backup name")

    backup_dir = DATA_PATH / "backups"
    db_file = backup_dir / f"{name}-db.sql"
    data_file = backup_dir / f"{name}-data.tar.gz"

    if db_file.exists():
        db_file.unlink()
    if data_file.exists():
        data_file.unlink()

    return {"success": True, "message": f"Backup {name} deleted"}


@app.post("/restore/{name}", dependencies=[Depends(require_jwt)])
def restore_backup(name: str):
    """Restore from backup (background). `nextcloudctl restore` takes long
    enough (tar extraction + in-container chown) to stay detached rather
    than go through the blocking `ctl()` helper, but it still runs via
    `sudo -n nextcloudctl` (ref #429 I3), never a bare non-sudo invocation.
    `nextcloudctl restore` also prompts yes/no on stdin -- answered here so
    the background job doesn't hang waiting on a TTY that will never come."""
    if not _valid_backup_name(name):
        raise HTTPException(400, "invalid backup name")

    proc = subprocess.Popen(
        ["sudo", "-n", CTL, "restore", name],
        stdin=subprocess.PIPE,
        stdout=open("/var/log/nextcloud-restore.log", "w"),
        stderr=subprocess.STDOUT
    )
    try:
        if proc.stdin:
            proc.stdin.write(b"yes\n")
            proc.stdin.close()
    except Exception:
        pass
    return {"success": True, "message": "Restore started in background"}


@app.get("/connections", dependencies=[Depends(require_jwt)])
def get_connections():
    """Get connection URLs (CalDAV, CardDAV, WebDAV)"""
    base_url = public_url()

    return {
        "base_url": base_url,
        "caldav": f"{base_url}/remote.php/dav/calendars/<username>/",
        "carddav": f"{base_url}/remote.php/dav/addressbooks/users/<username>/contacts/",
        "webdav": f"{base_url}/remote.php/dav/files/<username>/",
        "davx5_url": f"{base_url}/remote.php/dav",
        "desktop_url": base_url,
        "ios_app": "https://apps.apple.com/app/nextcloud/id1125420102",
        "android_app": "https://play.google.com/store/apps/details?id=com.nextcloud.client"
    }


class OccCommand(BaseModel):
    command: str


@app.post("/occ", dependencies=[Depends(require_jwt)])
def run_occ(req: OccCommand):
    """Run OCC command"""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    success, out, err = occ_cmd(req.command, timeout=120)
    if success:
        return {"success": True, "output": out}
    raise HTTPException(500, f"Command failed: {err}")


@app.get("/logs", dependencies=[Depends(require_jwt)])
def get_logs(lines: int = 100):
    """Get Nextcloud logs"""
    logs = []

    # Installation log
    install_log = Path("/var/log/nextcloud-install.log")
    if install_log.exists():
        success, out, _ = run_cmd(["tail", f"-n{lines}", str(install_log)])
        if success:
            logs.extend(out.split("\n"))

    return {"logs": logs}


class SSLEnable(BaseModel):
    domain: str


@app.post("/ssl/enable", dependencies=[Depends(require_jwt)])
def ssl_enable(req: SSLEnable):
    """Enable SSL for domain.

    NOTE (ref #429 I3): nextcloudctl has no `ssl-enable`/`ssl enable`
    subcommand at all (checked the full dispatch in sbin/nextcloudctl --
    there is no "ssl" case, only vhost/TLS termination is handled upstream by
    HAProxy). Left calling the standalone binary directly, unrouted through
    ctl()/sudo, as instructed -- it will keep failing (unknown command) until
    a real `nextcloudctl ssl-*` arm exists. Not invented here."""
    success, _, err = run_cmd(
        ["/usr/sbin/nextcloudctl", "ssl-enable", req.domain]
    )
    if success:
        return {"success": True, "message": f"SSL enabled for {req.domain}"}
    raise HTTPException(500, f"SSL enable failed: {err}")


@app.post("/ssl/disable", dependencies=[Depends(require_jwt)])
def ssl_disable():
    """Disable SSL. See NOTE on /ssl/enable -- no matching nextcloudctl
    subcommand exists; left as-is (ref #429 I3)."""
    success, _, err = run_cmd(["/usr/sbin/nextcloudctl", "ssl-disable"])
    if success:
        return {"success": True, "message": "SSL disabled"}
    raise HTTPException(500, f"SSL disable failed: {err}")
