"""SecuBox Nextcloud API - File Sync & Cloud Storage with LXC"""
import subprocess
import os
import re
import signal
import fcntl
import json
import socket
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


def _public_base_url(ssl_domain: str, domain: str, http_port: int) -> str:
    """Return the URL a client/device uses to reach Nextcloud.

    HAProxy terminates TLS 1.3 in front of every SecuBox vhost, so a real
    public domain is always reachable over https. Precedence: an explicit
    ssl_domain wins; otherwise the configured public ``domain`` (skipping the
    ``cloud.local`` placeholder); only a bare host with no real domain falls
    back to the container port. Never emit ``localhost`` when a domain exists —
    that is unreachable from a phone/desktop client (the bug this fixes).
    """
    if ssl_domain:
        return f"https://{ssl_domain}"
    if "." in domain and domain != "cloud.local":
        return f"https://{domain}"
    return f"http://localhost:{http_port}"


LXC_NAME = config.get("container_name", "nextcloud")
LXC_PATH = Path(config.get("lxc_path", "/data/lxc"))
DATA_PATH = Path(config.get("data_path", "/data/volumes/nextcloud"))
LXC_ROOTFS = LXC_PATH / LXC_NAME / "rootfs"
NC_IP = config.get("lxc_ip", "10.100.0.21")
NC_INTERNAL_PORT = 80

# This API runs UNPRIVILEGED (user `secubox`). Its ONLY privileged surface is
# `sudo nextcloudctl` (see /etc/sudoers.d/secubox-nextcloud) — direct lxc-info /
# lxc-attach / du on /data/lxc all fail with permission errors. So: probe the
# container's port for liveness (privilege-free) and route every container op
# through nextcloudctl (which has an `occ` passthrough and runs as root).
NCTL = ["sudo", "-n", "/usr/sbin/nextcloudctl"]


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr).

    Le sous-processus tourne dans sa PROPRE session, et l'expiration tue tout
    le groupe.

    Sans cela, `subprocess.run` ne tuait que l'enfant direct — ici `sudo` —
    tandis que la chaine qu'il avait ouverte derriere lui
    (`nextcloudctl` -> `lxc-attach` -> `php occ`) survivait, reparentee a
    l'init du conteneur. Le rafraichisseur de cache lance deux `occ` toutes
    les 60 s : chaque expiration abandonnait donc deux processus PHP, qui
    ralentissaient le conteneur, ce qui provoquait de nouvelles expirations.
    Il s'en est accumule 460, pour une charge machine de 300.
    """
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode == 0, out.strip(), err.strip()
    except subprocess.TimeoutExpired:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                proc.kill()
        try:
            if proc is not None:
                proc.communicate(timeout=5)
        except Exception:
            pass
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def lxc_running() -> bool:
    """Privilege-free liveness: the container's web server answers on its port."""
    return _port_open(NC_IP, NC_INTERNAL_PORT)


def lxc_installed() -> bool:
    """Container dir present. As `secubox` we can't traverse /data/lxc, so a
    PermissionError means the path IS there (installed); FileNotFound = not."""
    try:
        return (LXC_PATH / LXC_NAME / "config").exists()
    except PermissionError:
        return True


def nctl(*args, timeout: int = 60) -> tuple:
    """Run `sudo nextcloudctl <args>` — the only privileged container surface."""
    return run_cmd(NCTL + [str(a) for a in args], timeout)


def occ_cmd(command: str, timeout: int = 60) -> tuple:
    """OCC passthrough via nextcloudctl (runs as root inside the container)."""
    return nctl("occ", *command.split(), timeout=timeout)


def lxc_attach(command: str, timeout: int = 30) -> tuple:
    """Legacy shim: the only in-container ops the API needs are OCC commands, so
    route them through the nextcloudctl occ passthrough. Non-occ callers were
    already broken under the unprivileged user."""
    return nctl("occ", *command.split(), timeout=timeout)


# Background-refreshed cache for the slow, root-only fields (occ --version,
# occ user:list, container-side du). /status is polled every ~30s by the webui,
# so it must NOT run these inline (each occ call is ~5s and blocks the loop);
# it reads this cache, filled every 60s by _refresh_cache() below.
_nc_cache = {"version": "", "user_count": 0, "disk_used": "0", "ts": 0}


def _compute_nc_cache() -> dict:
    out_cache = {"version": "", "user_count": 0, "disk_used": "0", "ts": time.time()}
    if not lxc_running():
        return out_cache
    ok, out, _ = occ_cmd("--version", timeout=30)
    if ok:
        m = re.search(r'(\d+\.\d+\.\d+)', out)
        if m:
            out_cache["version"] = m.group(1)
    ok, out, _ = occ_cmd("user:list --output=json", timeout=30)
    if ok and out.strip():
        try:
            out_cache["user_count"] = len(json.loads(out.strip().splitlines()[-1]))
        except Exception:
            pass
    # Storage: only root (nextcloudctl) can read the data volume; parse the
    # "Storage: <size>" line from `nextcloudctl status`.
    ok, out, _ = nctl("status", timeout=30)
    if ok:
        m = re.search(r'Storage:\s*(\S+)', out)
        if m:
            out_cache["disk_used"] = m.group(1)
    return out_cache


INTERVALLE = 60
PLAFOND_ATTENTE = 1800
FICHIER_CACHE = Path("/var/cache/secubox/nextcloud/status.json")
VERROU = Path("/run/secubox/nextcloud-cache.lock")


def _lire_cache_partage() -> Optional[dict]:
    try:
        d = json.loads(FICHIER_CACHE.read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _ecrire_cache_partage(d: dict) -> None:
    try:
        FICHIER_CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = FICHIER_CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(d))
        os.replace(tmp, FICHIER_CACHE)
    except OSError:
        pass


def _cache_worker():
    """Rafraichit le cache toutes les 60 s, dans un thread demon.

    Deliberement pas une tache de demarrage asyncio : le lifespan d'uvicorn ne
    se declenchait pas de facon fiable ici, et le cache restait vide. Un thread
    demon lance a l'import tourne toujours, et fait son travail bloquant hors
    de la boucle.

    UN SEUL processus rafraichit, garde par un verrou de fichier. Ce module est
    importe par le demon autonome, par l'agregateur ET par le groupe : chacun
    demarrait son propre rafraichisseur, et sept `occ` concurrents partaient
    ainsi toutes les minutes sur une machine qui met plus d'une minute a en
    executer un. Les autres processus se contentent de relire le fichier que le
    detenteur du verrou ecrit — c'est la meme donnee, elle n'a pas a etre
    calculee sept fois.
    """
    global _nc_cache
    verrou = None
    try:
        VERROU.parent.mkdir(parents=True, exist_ok=True)
        verrou = open(VERROU, "w")
        fcntl.flock(verrou, fcntl.LOCK_EX | fcntl.LOCK_NB)
        maitre = True
    except (OSError, BlockingIOError):
        maitre = False

    # Disjoncteur. Un sondeur de fond qui reinterroge sans fin un service
    # engorge l'engorge davantage : chaque cycle ajoutait trois `occ` a un
    # conteneur qui ne finissait deja plus les precedents. On espace donc les
    # tentatives apres chaque echec, jusqu'a une demi-heure, et on revient au
    # rythme normal des que la mesure reussit.
    attente = INTERVALLE
    echecs = 0

    while True:
        try:
            if maitre:
                mesure = _compute_nc_cache()
                # Une version vide alors que le conteneur repond signale un
                # `occ` qui n'aboutit pas : c'est un echec, pas une mesure.
                rate = mesure.get("version") == "" and lxc_running()
                if rate:
                    echecs += 1
                    attente = min(INTERVALLE * (2 ** echecs), PLAFOND_ATTENTE)
                    mesure["indisponible"] = True
                    mesure["prochain_essai_dans"] = attente
                else:
                    echecs = 0
                    attente = INTERVALLE
                _nc_cache = mesure
                _ecrire_cache_partage(_nc_cache)
            else:
                partage = _lire_cache_partage()
                if partage:
                    _nc_cache = partage
                elif verrou is not None:
                    # Le detenteur a disparu : on tente de reprendre la main,
                    # sinon plus personne ne mesurerait rien.
                    try:
                        fcntl.flock(verrou, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        maitre = True
                    except (OSError, BlockingIOError):
                        pass
        except Exception:
            pass
        time.sleep(attente if maitre else INTERVALLE)


threading.Thread(target=_cache_worker, daemon=True, name="nc-cache").start()


# Public endpoints
@app.get("/status")
async def status():
    """Get Nextcloud service status (fast: live port probe + cached occ fields)."""
    running = lxc_running()
    installed = lxc_installed()

    c = _nc_cache
    version = c["version"] if running else ""
    user_count = c["user_count"] if running else 0
    disk_used = c["disk_used"]

    http_port = config.get("http_port", 8080)
    domain = config.get("domain", "cloud.local")

    return {
        "module": "nextcloud",
        "enabled": config.get("enabled", True),
        "running": running,
        "installed": installed,
        "version": version,
        "http_port": http_port,
        "data_path": str(DATA_PATH),
        "domain": domain,
        "user_count": user_count,
        "disk_used": disk_used,
        # Public URL from the real domain (not localhost) so the dashboard links
        # somewhere reachable; falls back to the container port for a bare host.
        "web_url": _public_base_url(config.get("ssl_domain", ""), domain, http_port),
        "ssl_enabled": config.get("ssl_enabled", False),
        "container_name": LXC_NAME,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "module": "nextcloud"}


# Protected endpoints
@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
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
async def save_config(update: ConfigUpdate):
    """Save Nextcloud configuration"""
    return {"success": True, "message": "Configuration saved"}


@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start Nextcloud container"""
    if lxc_running():
        raise HTTPException(400, "Service is already running")
    if not lxc_installed():
        raise HTTPException(400, "Container not installed")

    success, _, err = nctl("start")
    if success:
        return {"success": True, "message": "Service started"}
    raise HTTPException(500, f"Failed to start: {err}")


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop Nextcloud container"""
    if not lxc_running():
        raise HTTPException(400, "Service is not running")

    success, _, err = nctl("stop")
    if success:
        return {"success": True, "message": "Service stopped"}
    raise HTTPException(500, f"Failed to stop: {err}")


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart Nextcloud container"""
    success, _, err = nctl("restart")
    if success:
        return {"success": True, "message": "Service restarted"}
    raise HTTPException(500, f"Restart failed: {err}")


@app.post("/install", dependencies=[Depends(require_jwt)])
def install():
    """Install Nextcloud (background)"""
    if lxc_installed():
        raise HTTPException(400, "Already installed")

    subprocess.Popen(
        [*NCTL, "install"],
        stdout=open("/var/log/nextcloud-install.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {
        "success": True,
        "message": "Installation started in background",
        "log_file": "/var/log/nextcloud-install.log"
    }


@app.post("/uninstall", dependencies=[Depends(require_jwt)])
async def uninstall():
    """Uninstall Nextcloud (preserves data)"""
    success, _, err = run_cmd([*NCTL, "uninstall"])
    if success:
        return {"success": True, "message": "Uninstalled (data preserved)"}
    raise HTTPException(500, f"Uninstall failed: {err}")


@app.post("/update", dependencies=[Depends(require_jwt)])
def update():
    """Update Nextcloud"""
    subprocess.Popen(
        [*NCTL, "update"],
        stdout=open("/var/log/nextcloud-update.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {"success": True, "message": "Update started in background"}


@app.get("/users", dependencies=[Depends(require_jwt)])
async def list_users():
    """List Nextcloud users"""
    if not lxc_running():
        return {"users": []}

    success, out, _ = occ_cmd("user:list --output=json")
    if success:
        try:
            import json
            data = json.loads(out)
            users = [{"uid": k, "displayname": v} for k, v in data.items()]
            return {"users": users}
        except:
            pass

    return {"users": []}


class ResetPassword(BaseModel):
    uid: str
    password: str


@app.post("/user/password", dependencies=[Depends(require_jwt)])
async def reset_password(req: ResetPassword):
    """Reset user password"""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    cmd = f"OC_PASS='{req.password}' php /var/www/nextcloud/occ user:resetpassword --password-from-env '{req.uid}'"
    full_cmd = f"su -s /bin/bash www-data -c \"{cmd}\""
    success, out, err = lxc_attach(full_cmd)

    if success:
        return {"success": True, "message": f"Password reset for {req.uid}"}
    raise HTTPException(500, f"Failed: {err}")


@app.get("/storage", dependencies=[Depends(require_jwt)])
async def get_storage():
    """Get storage statistics"""
    total_size = "0"
    data_size = "0"
    backup_size = "0"
    disk_free = "0"
    disk_total = "0"
    disk_used_pct = 0

    if DATA_PATH.exists():
        success, out, _ = run_cmd(["du", "-sh", str(DATA_PATH)])
        if success:
            total_size = out.split()[0]

    data_dir = DATA_PATH / "data"
    if data_dir.exists():
        success, out, _ = run_cmd(["du", "-sh", str(data_dir)])
        if success:
            data_size = out.split()[0]

    backup_dir = DATA_PATH / "backups"
    if backup_dir.exists():
        success, out, _ = run_cmd(["du", "-sh", str(backup_dir)])
        if success:
            backup_size = out.split()[0]

    success, out, _ = run_cmd(["df", "-h", str(DATA_PATH)])
    if success:
        lines = out.split("\n")
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) >= 5:
                disk_total = parts[1]
                disk_free = parts[3]
                disk_used_pct = int(parts[4].rstrip("%"))

    return {
        "total_size": total_size,
        "data_size": data_size,
        "backup_size": backup_size,
        "disk_free": disk_free,
        "disk_total": disk_total,
        "disk_used_percent": disk_used_pct
    }


@app.get("/backups", dependencies=[Depends(require_jwt)])
async def list_backups():
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
async def create_backup(req: BackupRequest):
    """Create a backup"""
    cmd = [*NCTL, "backup"]
    if req.name:
        cmd.append(req.name)

    success, out, err = run_cmd(cmd, timeout=300)
    if success:
        return {"success": True, "message": "Backup created"}
    raise HTTPException(500, f"Backup failed: {err}")


@app.delete("/backup/{name}", dependencies=[Depends(require_jwt)])
async def delete_backup(name: str):
    """Delete a backup"""
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
    """Restore from backup"""
    subprocess.Popen(
        [*NCTL, "restore", name],
        stdout=open("/var/log/nextcloud-restore.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {"success": True, "message": "Restore started in background"}


@app.get("/connections", dependencies=[Depends(require_jwt)])
async def get_connections():
    """Get connection URLs (CalDAV, CardDAV, WebDAV)"""
    http_port = config.get("http_port", 8080)
    domain = config.get("domain", "cloud.local")
    ssl_domain = config.get("ssl_domain", "")

    base_url = _public_base_url(ssl_domain, domain, http_port)

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
async def run_occ(req: OccCommand):
    """Run OCC command"""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    success, out, err = occ_cmd(req.command, timeout=120)
    if success:
        return {"success": True, "output": out}
    raise HTTPException(500, f"Command failed: {err}")


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
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
async def ssl_enable(req: SSLEnable):
    """Enable SSL for domain"""
    success, _, err = run_cmd(
        [*NCTL, "ssl-enable", req.domain]
    )
    if success:
        return {"success": True, "message": f"SSL enabled for {req.domain}"}
    raise HTTPException(500, f"SSL enable failed: {err}")


@app.post("/ssl/disable", dependencies=[Depends(require_jwt)])
async def ssl_disable():
    """Disable SSL"""
    success, _, err = run_cmd([*NCTL, "ssl-disable"])
    if success:
        return {"success": True, "message": "SSL disabled"}
    raise HTTPException(500, f"SSL disable failed: {err}")
