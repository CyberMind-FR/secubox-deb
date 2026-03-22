"""SecuBox Mail API - Unified Mail Server + Webmail Management

Three-fold perspective:
1. Components: Mail server (Postfix/Dovecot LXC) + Webmail (Roundcube LXC)
2. Status: Running state, ports, users, storage, certificates
3. Access: Connection URLs, client configs, webmail URL

SecuBox is an appliance and network model - distributed peer applications.
"""
import subprocess
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Mail", version="1.0.0")
config = get_config("mail")

DATA_PATH = Path(config.get("data_path", "/srv/mail"))
LXC_PATH = Path(config.get("lxc_path", "/srv/lxc"))
MAIL_CONTAINER = config.get("mail_container", "mailserver")
WEBMAIL_CONTAINER = config.get("webmail_container", "roundcube")
DOMAIN = config.get("domain", "secubox.local")
HOSTNAME = config.get("hostname", "mail")
MAIL_IP = config.get("mail_ip", "192.168.255.30")
WEBMAIL_PORT = config.get("webmail_port", 8027)


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def lxc_running(name: str) -> bool:
    """Check if LXC container is running"""
    success, out, _ = run_cmd(["lxc-info", "-n", name, "-s"])
    return success and "RUNNING" in out


def lxc_exists(name: str) -> bool:
    """Check if LXC container exists"""
    return (LXC_PATH / name / "rootfs").exists()


def lxc_attach(name: str, command: str, timeout: int = 30) -> tuple:
    """Execute command inside LXC container"""
    cmd = ["lxc-attach", "-n", name, "--", "sh", "-c", command]
    return run_cmd(cmd, timeout)


# =============================================================================
# STATUS - Module state and health
# =============================================================================

@app.get("/status")
async def status():
    """Get unified mail status (public endpoint)"""
    mail_running = lxc_running(MAIL_CONTAINER)
    mail_installed = lxc_exists(MAIL_CONTAINER)
    webmail_running = lxc_running(WEBMAIL_CONTAINER)
    webmail_installed = lxc_exists(WEBMAIL_CONTAINER)

    # Count users
    user_count = 0
    users_file = DATA_PATH / "config" / "users"
    if users_file.exists():
        user_count = sum(1 for line in users_file.read_text().splitlines() if line.strip())

    # Storage usage
    storage = "0"
    if (DATA_PATH / "mail").exists():
        success, out, _ = run_cmd(["du", "-sh", str(DATA_PATH / "mail")])
        if success:
            storage = out.split()[0]

    # Check ports
    ports_status = {}
    if mail_running:
        success, out, _ = lxc_attach(MAIL_CONTAINER, "netstat -tln")
        if success:
            for port in [25, 587, 465, 143, 993, 110, 995]:
                ports_status[port] = f":{port} " in out

    return {
        "module": "mail",
        "version": "1.0.0",
        "enabled": config.get("enabled", True),
        "domain": DOMAIN,
        "hostname": f"{HOSTNAME}.{DOMAIN}",
        "components": {
            "mail_server": {
                "name": MAIL_CONTAINER,
                "installed": mail_installed,
                "running": mail_running,
                "ip": MAIL_IP if mail_running else None,
            },
            "webmail": {
                "name": WEBMAIL_CONTAINER,
                "installed": webmail_installed,
                "running": webmail_running,
                "port": WEBMAIL_PORT if webmail_running else None,
            }
        },
        "user_count": user_count,
        "storage": storage,
        "ports": ports_status,
        "running": mail_running and webmail_running,
        "installed": mail_installed and webmail_installed,
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    mail_ok = lxc_running(MAIL_CONTAINER)
    webmail_ok = lxc_running(WEBMAIL_CONTAINER)
    return {
        "status": "ok" if (mail_ok and webmail_ok) else "degraded",
        "mail_server": "ok" if mail_ok else "down",
        "webmail": "ok" if webmail_ok else "down",
    }


# =============================================================================
# ACCESS - Connection URLs and client configuration
# =============================================================================

@app.get("/access")
async def get_access():
    """Get connection URLs and client configuration (public)"""
    fqdn = f"{HOSTNAME}.{DOMAIN}"
    ssl_enabled = (DATA_PATH / "ssl" / "fullchain.pem").exists()

    return {
        "domain": DOMAIN,
        "mail_server": fqdn,
        "imap": {"host": fqdn, "port": 993, "ssl": True, "starttls_port": 143},
        "smtp": {"host": fqdn, "port": 587, "ssl": False, "starttls": True, "ssl_port": 465},
        "pop3": {"host": fqdn, "port": 995, "ssl": True},
        "webmail": {
            "url": f"https://webmail.{DOMAIN}",
            "local_url": f"http://localhost:{WEBMAIL_PORT}",
        },
        "ssl_enabled": ssl_enabled,
        "apps": {
            "thunderbird": f"https://autoconfig.{DOMAIN}/mail/config-v1.1.xml",
            "outlook": f"https://autodiscover.{DOMAIN}/autodiscover/autodiscover.xml",
            "apple": f"https://{fqdn}/{DOMAIN}.mobileconfig",
        }
    }


# =============================================================================
# USERS - User and alias management
# =============================================================================

class UserCreate(BaseModel):
    email: str
    password: str

class UserPassword(BaseModel):
    email: str
    password: str

class AliasCreate(BaseModel):
    alias: str
    target: str


@app.get("/users", dependencies=[Depends(require_jwt)])
async def list_users():
    """List mail users"""
    users = []
    users_file = DATA_PATH / "config" / "users"

    if users_file.exists():
        for line in users_file.read_text().splitlines():
            if not line.strip():
                continue
            parts = line.split(":")
            if len(parts) >= 1:
                email = parts[0]
                domain = email.split("@")[1] if "@" in email else ""
                user = email.split("@")[0] if "@" in email else email
                maildir = DATA_PATH / "mail" / domain / user
                size = "0"
                messages = 0
                if maildir.exists():
                    success, out, _ = run_cmd(["du", "-sh", str(maildir)])
                    if success:
                        size = out.split()[0]
                users.append({"email": email, "size": size, "messages": messages})

    return {"users": users, "count": len(users)}


@app.post("/user", dependencies=[Depends(require_jwt)])
async def create_user(user: UserCreate):
    """Create mail user"""
    success, out, err = run_cmd(["/usr/sbin/mailctl", "user", "add", user.email, user.password])
    if success:
        return {"success": True, "message": f"User {user.email} created"}
    raise HTTPException(500, f"Failed: {err}")


@app.delete("/user/{email}", dependencies=[Depends(require_jwt)])
async def delete_user(email: str):
    """Delete mail user"""
    success, _, err = run_cmd(["/usr/sbin/mailctl", "user", "del", email])
    if success:
        return {"success": True, "message": f"User {email} deleted"}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/user/password", dependencies=[Depends(require_jwt)])
async def change_password(req: UserPassword):
    """Change user password"""
    success, _, err = run_cmd(["/usr/sbin/mailctl", "user", "passwd", req.email, req.password])
    if success:
        return {"success": True, "message": "Password changed"}
    raise HTTPException(500, f"Failed: {err}")


@app.get("/aliases", dependencies=[Depends(require_jwt)])
async def list_aliases():
    """List email aliases"""
    aliases = []
    virtual_file = DATA_PATH / "config" / "virtual"
    if virtual_file.exists():
        for line in virtual_file.read_text().splitlines():
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    aliases.append({"alias": parts[0], "target": parts[1]})
    return {"aliases": aliases, "count": len(aliases)}


@app.post("/alias", dependencies=[Depends(require_jwt)])
async def create_alias(alias: AliasCreate):
    """Create email alias"""
    success, _, err = run_cmd(["/usr/sbin/mailctl", "alias", "add", alias.alias, alias.target])
    if success:
        return {"success": True, "message": f"Alias created"}
    raise HTTPException(500, f"Failed: {err}")


@app.delete("/alias/{alias_email}", dependencies=[Depends(require_jwt)])
async def delete_alias(alias_email: str):
    """Delete email alias"""
    success, _, err = run_cmd(["/usr/sbin/mailctl", "alias", "del", alias_email])
    if success:
        return {"success": True}
    raise HTTPException(500, f"Failed: {err}")


# =============================================================================
# SERVICE CONTROL
# =============================================================================

@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start mail services"""
    success, _, err = run_cmd(["/usr/sbin/mailctl", "start"])
    if success:
        return {"success": True, "message": "Services started"}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop mail services"""
    success, _, err = run_cmd(["/usr/sbin/mailctl", "stop"])
    if success:
        return {"success": True, "message": "Services stopped"}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart mail services"""
    success, _, err = run_cmd(["/usr/sbin/mailctl", "restart"])
    if success:
        return {"success": True}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install_service(background_tasks: BackgroundTasks):
    """Install mail services (background)"""
    def do_install():
        subprocess.run(["/usr/sbin/mailctl", "install"],
                      stdout=open("/var/log/mail-install.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_install)
    return {"success": True, "message": "Installation started"}


# =============================================================================
# MIGRATION
# =============================================================================

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"


@app.post("/migrate", dependencies=[Depends(require_jwt)])
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks):
    """Migrate mail data from OpenWrt source"""
    def do_migrate():
        subprocess.run(["/usr/sbin/mailctl", "migrate", req.source],
                      stdout=open("/var/log/mail-migrate.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_migrate)
    return {"success": True, "message": f"Migration from {req.source} started"}


# =============================================================================
# BACKUP / RESTORE
# =============================================================================

@app.get("/backups", dependencies=[Depends(require_jwt)])
async def list_backups():
    """List available backups"""
    backups = []
    backup_dir = DATA_PATH / "backups"
    if backup_dir.exists():
        for f in backup_dir.glob("mail_*.tar.gz"):
            stat = f.stat()
            backups.append({
                "name": f.name,
                "size": f"{stat.st_size // 1024 // 1024}M",
                "timestamp": int(stat.st_mtime),
            })
    return {"backups": sorted(backups, key=lambda x: x["timestamp"], reverse=True)}


@app.post("/backup", dependencies=[Depends(require_jwt)])
async def create_backup():
    """Create backup"""
    success, out, err = run_cmd(["/usr/sbin/mailctl", "backup"])
    if success:
        return {"success": True, "file": out}
    raise HTTPException(500, f"Backup failed: {err}")


@app.post("/restore/{backup_name}", dependencies=[Depends(require_jwt)])
async def restore_backup(backup_name: str, background_tasks: BackgroundTasks):
    """Restore from backup"""
    backup_file = DATA_PATH / "backups" / backup_name
    if not backup_file.exists():
        raise HTTPException(404, "Backup not found")
    def do_restore():
        subprocess.run(["/usr/sbin/mailctl", "restore", str(backup_file)],
                      stdout=open("/var/log/mail-restore.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_restore)
    return {"success": True, "message": "Restore started"}


# =============================================================================
# LOGS & SSL
# =============================================================================

@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
    """Get mail logs"""
    if not lxc_running(MAIL_CONTAINER):
        return {"logs": [], "error": "Container not running"}
    success, out, _ = lxc_attach(MAIL_CONTAINER, f"tail -n {lines} /var/log/mail.log")
    return {"logs": out.split("\n") if success else []}


@app.get("/ssl", dependencies=[Depends(require_jwt)])
async def get_ssl_status():
    """Get SSL certificate status"""
    cert_file = DATA_PATH / "ssl" / "fullchain.pem"
    if not cert_file.exists():
        return {"installed": False}
    success, out, _ = run_cmd(["openssl", "x509", "-in", str(cert_file), "-noout", "-subject", "-dates"])
    if success:
        info = {}
        for line in out.split("\n"):
            if "=" in line:
                key, val = line.split("=", 1)
                info[key.strip().lower()] = val.strip()
        return {"installed": True, **info}
    return {"installed": True}


@app.post("/ssl/setup", dependencies=[Depends(require_jwt)])
async def setup_ssl(background_tasks: BackgroundTasks):
    """Setup SSL certificate"""
    def do_setup():
        subprocess.run(["/usr/sbin/mailctl", "ssl", "setup"],
                      stdout=open("/var/log/mail-ssl.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_setup)
    return {"success": True, "message": "SSL setup started"}
