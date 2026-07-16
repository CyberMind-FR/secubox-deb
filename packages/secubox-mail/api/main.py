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
import socket
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import Response
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Mail", version="2.2.0")
config = get_config("mail")

# Phase 2: mount rspamd router + legacy deprecation shims
from .routers import rspamd as _rspamd_router
from .routers import legacy as _legacy_router
app.include_router(_rspamd_router.router)
app.include_router(_legacy_router.router)

# Canonical config keys (Phase 1 rev. 2). Legacy keys are accepted as
# fallback for one release so deploys mid-upgrade don't break.
DATA_PATH = Path(config.get("data_path", "/data/volumes/mail"))
LXC_PATH = Path(config.get("lxc_path", "/data/lxc"))
CONTAINER = config.get("container", config.get("mail_container", "mail"))
# Legacy alias retained for callers that still reference WEBMAIL_CONTAINER —
# webmail is now in the same single LXC.
MAIL_CONTAINER = CONTAINER
WEBMAIL_CONTAINER = CONTAINER
DOMAIN = config.get("domain", "secubox.local")
HOSTNAME = config.get("hostname", "mail")
LXC_IP = config.get("lxc_ip", config.get("mail_ip", "10.100.0.10"))
LXC_BRIDGE = config.get("lxc_bridge", "br-lxc")
LXC_GATEWAY = config.get("lxc_gateway", "10.100.0.1")
# Webmail is on standard HTTP inside the LXC; host nginx proxies via :443.
WEBMAIL_PORT = 80
# Roundcube nginx answers on its own container IP (may differ from the mail IP).
WEBMAIL_IP = config.get("webmail_ip", "10.100.0.12")
# Back-compat alias for any caller still reading MAIL_IP.
MAIL_IP = LXC_IP

# The mail service ports we surface in the dashboard (label + purpose).
MAIL_PORTS = [
    (25, "SMTP"), (587, "Submission"), (465, "SMTPS"),
    (143, "IMAP"), (993, "IMAPS"), (110, "POP3"), (995, "POP3S"),
]


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
    success, out, _ = run_cmd(["lxc-info", "-P", str(LXC_PATH), "-n", name, "-s"])
    return success and "RUNNING" in out


def lxc_exists(name: str) -> bool:
    """Check if LXC container exists"""
    return (LXC_PATH / name / "rootfs").exists()


def lxc_attach(name: str, command: str, timeout: int = 30) -> tuple:
    """Execute command inside LXC container"""
    cmd = ["lxc-attach", "-P", str(LXC_PATH), "-n", name, "--", "sh", "-c", command]
    return run_cmd(cmd, timeout)


def port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """True if a TCP connection to host:port succeeds. This is the source of
    truth for 'is the service up' — it needs no privilege and does not depend on
    the LXC path/name, so it stays correct across container-layout changes (the
    lxc-info path drifted to /var/lib/lxc and made everything read 'Stopped')."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_mail_ports() -> Dict[int, bool]:
    """Live status of every mail port, by direct TCP probe."""
    return {p: port_open(LXC_IP, p) for p, _ in MAIL_PORTS}


def mail_server_up() -> bool:
    """Mail server is up if it answers on SMTP or IMAP."""
    return port_open(LXC_IP, 25) or port_open(LXC_IP, 143)


def webmail_up() -> bool:
    """Webmail is up if Roundcube's HTTP answers."""
    return port_open(WEBMAIL_IP, WEBMAIL_PORT)


# =============================================================================
# STATUS - Module state and health
# =============================================================================

@app.get("/status")
async def status():
    """Get unified mail status (public endpoint)"""
    # Running state comes from live TCP probes, not lxc-info (which silently
    # broke when lxc_path drifted to /var/lib/lxc). Installed = rootfs present.
    mail_running = mail_server_up()
    mail_installed = lxc_exists(MAIL_CONTAINER)
    webmail_running = webmail_up()
    webmail_installed = lxc_exists(WEBMAIL_CONTAINER)

    # Count users
    user_count = 0
    users_file = DATA_PATH / "config" / "users"
    if users_file.exists():
        user_count = sum(1 for line in users_file.read_text().splitlines() if line.strip())

    # Storage usage — virtual mailboxes live under DATA_PATH/vmail.
    storage = "0"
    vmail_dir = DATA_PATH / "vmail"
    if vmail_dir.exists():
        success, out, _ = run_cmd(["du", "-sh", str(vmail_dir)])
        if success and out:
            storage = out.split()[0]

    # Live per-port status via direct TCP probe (always evaluated).
    ports_status = {p: up for p, up in probe_mail_ports().items()}

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
    mail_ok = mail_server_up()
    webmail_ok = webmail_up()
    return {
        "status": "ok" if (mail_ok and webmail_ok) else "degraded",
        "mail_server": "ok" if mail_ok else "down",
        "webmail": "ok" if webmail_ok else "down",
    }


# =============================================================================
# COMPONENTS - Three-fold architecture (What)
# =============================================================================

@app.get("/components")
async def get_components():
    """List system components (public, three-fold: what)"""
    return {
        "components": [
            {
                "name": "Mail Server",
                "type": "lxc",
                "container": MAIL_CONTAINER,
                "description": "Postfix + Dovecot mail server",
                "installed": lxc_exists(MAIL_CONTAINER),
                "running": mail_server_up(),
                "ports": [25, 587, 465, 143, 993, 110, 995],
                "ip": MAIL_IP,
            },
            {
                "name": "Webmail",
                "type": "lxc",
                "container": WEBMAIL_CONTAINER,
                "description": "Roundcube webmail interface",
                "installed": lxc_exists(WEBMAIL_CONTAINER),
                "running": webmail_up(),
                "port": WEBMAIL_PORT,
            },
            {
                "name": "User Database",
                "type": "file",
                "path": str(DATA_PATH / "config" / "users"),
                "description": "Dovecot passwd-file users",
                "installed": True,
            },
            {
                "name": "SSL Certificates",
                "type": "file",
                "path": str(DATA_PATH / "ssl" / "fullchain.pem"),
                "description": "TLS certificates for mail server",
                "installed": (DATA_PATH / "ssl" / "fullchain.pem").exists(),
            },
        ]
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
# AUTODISCOVER - Email client auto-configuration
# =============================================================================

@app.get("/mail/config-v1.1.xml")
@app.get("/autoconfig/mail/config-v1.1.xml")
async def thunderbird_autoconfig():
    """Mozilla Thunderbird/Evolution autoconfig (RFC 6186 style)"""
    fqdn = f"{HOSTNAME}.{DOMAIN}"
    ssl_enabled = (DATA_PATH / "ssl" / "fullchain.pem").exists()

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{DOMAIN}">
    <domain>{DOMAIN}</domain>
    <displayName>{DOMAIN} Mail</displayName>
    <displayShortName>{DOMAIN}</displayShortName>

    <incomingServer type="imap">
      <hostname>{fqdn}</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>

    <incomingServer type="imap">
      <hostname>{fqdn}</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>

    <incomingServer type="pop3">
      <hostname>{fqdn}</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>

    <outgoingServer type="smtp">
      <hostname>{fqdn}</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>

    <outgoingServer type="smtp">
      <hostname>{fqdn}</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>

    <documentation url="https://webmail.{DOMAIN}">
      <descr lang="en">Webmail access</descr>
    </documentation>
  </emailProvider>
</clientConfig>"""

    return Response(content=xml, media_type="application/xml")


@app.get("/autodiscover/autodiscover.xml")
@app.post("/autodiscover/autodiscover.xml")
@app.post("/Autodiscover/Autodiscover.xml")
async def outlook_autodiscover(request: Request):
    """Microsoft Outlook/ActiveSync autodiscover"""
    fqdn = f"{HOSTNAME}.{DOMAIN}"

    # Try to extract email from POST request body
    email = ""
    if request.method == "POST":
        try:
            body = await request.body()
            body_str = body.decode("utf-8")
            # Extract email from XML: <EMailAddress>user@domain</EMailAddress>
            import re
            match = re.search(r"<EMailAddress>([^<]+)</EMailAddress>", body_str)
            if match:
                email = match.group(1)
        except Exception:
            pass

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>{fqdn}</Server>
        <Port>993</Port>
        <SSL>on</SSL>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>
        <LoginName>{email if email else "%EMAILADDRESS%"}</LoginName>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>{fqdn}</Server>
        <Port>587</Port>
        <SSL>on</SSL>
        <Encryption>TLS</Encryption>
        <SPA>off</SPA>
        <AuthRequired>on</AuthRequired>
        <LoginName>{email if email else "%EMAILADDRESS%"}</LoginName>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>"""

    return Response(content=xml, media_type="application/xml")


@app.get("/{domain}.mobileconfig")
async def apple_mobileconfig(domain: str):
    """Apple iOS/macOS mail configuration profile"""
    if domain != DOMAIN:
        raise HTTPException(404, "Domain not found")

    fqdn = f"{HOSTNAME}.{DOMAIN}"
    profile_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mail.{DOMAIN}"))
    payload_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mail.payload.{DOMAIN}"))

    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>EmailAccountDescription</key>
            <string>{DOMAIN} Mail</string>
            <key>EmailAccountName</key>
            <string>{DOMAIN}</string>
            <key>EmailAccountType</key>
            <string>EmailTypeIMAP</string>
            <key>EmailAddress</key>
            <string></string>
            <key>IncomingMailServerAuthentication</key>
            <string>EmailAuthPassword</string>
            <key>IncomingMailServerHostName</key>
            <string>{fqdn}</string>
            <key>IncomingMailServerPortNumber</key>
            <integer>993</integer>
            <key>IncomingMailServerUseSSL</key>
            <true/>
            <key>IncomingMailServerUsername</key>
            <string></string>
            <key>OutgoingMailServerAuthentication</key>
            <string>EmailAuthPassword</string>
            <key>OutgoingMailServerHostName</key>
            <string>{fqdn}</string>
            <key>OutgoingMailServerPortNumber</key>
            <integer>587</integer>
            <key>OutgoingMailServerUseSSL</key>
            <true/>
            <key>OutgoingMailServerUsername</key>
            <string></string>
            <key>OutgoingPasswordSameAsIncomingPassword</key>
            <true/>
            <key>PayloadDescription</key>
            <string>Configures email for {DOMAIN}</string>
            <key>PayloadDisplayName</key>
            <string>{DOMAIN} Email</string>
            <key>PayloadIdentifier</key>
            <string>com.secubox.mail.{DOMAIN}</string>
            <key>PayloadType</key>
            <string>com.apple.mail.managed</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PreventAppSheet</key>
            <false/>
            <key>PreventMove</key>
            <false/>
            <key>SMIMEEnabled</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Email configuration for {DOMAIN}</string>
    <key>PayloadDisplayName</key>
    <string>{DOMAIN} Mail Settings</string>
    <key>PayloadIdentifier</key>
    <string>com.secubox.mailconfig.{DOMAIN}</string>
    <key>PayloadOrganization</key>
    <string>SecuBox</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>"""

    return Response(
        content=plist,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": f'attachment; filename="{DOMAIN}.mobileconfig"'}
    )


@app.get("/.well-known/autoconfig/mail/config-v1.1.xml")
async def wellknown_autoconfig():
    """Well-known autoconfig location"""
    return await thunderbird_autoconfig()


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
    """Change a mail user's password.

    Writes the new SHA512-CRYPT hash directly into the dovecot passwd-file
    (DATA_PATH/config/users — the bind-mounted file the LXC actually reads). The
    legacy `mailctl user passwd` path wrote a host-only copy dovecot never reads,
    so the change silently didn't take (login kept failing). Hash is generated by
    the container's own doveadm so it matches the passdb scheme. Also normalises a
    legacy 2-field line to the full 8-field userdb format on the way through."""
    users_file = DATA_PATH / "config" / "users"
    if not users_file.exists():
        raise HTTPException(500, "users file not found")
    lines = users_file.read_text().splitlines()
    if not any(l.split(":", 1)[0] == req.email for l in lines if l.strip()):
        raise HTTPException(404, f"User {req.email} not found")
    ok, out, err = run_cmd(["lxc-attach", "-P", str(LXC_PATH), "-n", CONTAINER,
                            "--", "doveadm", "pw", "-s", "SHA512-CRYPT", "-p", req.password])
    new_hash = out.strip()
    if not ok or not new_hash.startswith("{"):
        raise HTTPException(500, f"hash generation failed: {err or out}")
    new_lines = []
    for l in lines:
        if l.strip() and l.split(":", 1)[0] == req.email:
            f = l.split(":")
            if len(f) >= 8:
                f[1] = new_hash
            else:  # legacy 2-field line → rebuild full userdb record
                domain = req.email.split("@")[1] if "@" in req.email else ""
                user = req.email.split("@")[0] if "@" in req.email else req.email
                f = [req.email, new_hash, "5000", "5000", "", f"/var/mail/{domain}/{user}", "", ""]
            l = ":".join(f)
        new_lines.append(l)
    users_file.write_text("\n".join(new_lines) + "\n")
    return {"success": True, "message": "Password changed"}


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
# WEBMAIL CONTROL (via roundcubectl)
# =============================================================================

@app.get("/webmail/status")
async def webmail_status():
    """Get webmail container status"""
    running = lxc_running(WEBMAIL_CONTAINER)
    installed = lxc_exists(WEBMAIL_CONTAINER)
    return {
        "container": WEBMAIL_CONTAINER,
        "installed": installed,
        "running": running,
        "url": f"https://webmail.{DOMAIN}" if running else None,
        "local_url": f"http://localhost:{WEBMAIL_PORT}" if running else None,
    }


@app.post("/webmail/start", dependencies=[Depends(require_jwt)])
async def webmail_start():
    """Start webmail container"""
    success, _, err = run_cmd(["/usr/sbin/roundcubectl", "start"])
    if success:
        return {"success": True, "message": "Webmail started"}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/webmail/stop", dependencies=[Depends(require_jwt)])
async def webmail_stop():
    """Stop webmail container"""
    success, _, err = run_cmd(["/usr/sbin/roundcubectl", "stop"])
    if success:
        return {"success": True, "message": "Webmail stopped"}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/webmail/restart", dependencies=[Depends(require_jwt)])
async def webmail_restart():
    """Restart webmail container"""
    success, _, err = run_cmd(["/usr/sbin/roundcubectl", "restart"])
    if success:
        return {"success": True, "message": "Webmail restarted"}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/webmail/install", dependencies=[Depends(require_jwt)])
async def webmail_install(background_tasks: BackgroundTasks):
    """Install webmail container (background)"""
    def do_install():
        subprocess.run(["/usr/sbin/roundcubectl", "install"],
                      stdout=open("/var/log/webmail-install.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_install)
    return {"success": True, "message": "Webmail installation started"}


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
        return {"installed": False, "type": None}

    # Get certificate info
    info = {"installed": True}
    success, out, _ = run_cmd(["openssl", "x509", "-in", str(cert_file),
                               "-noout", "-subject", "-dates", "-issuer"])
    if success:
        for line in out.split("\n"):
            if "=" in line:
                key, val = line.split("=", 1)
                info[key.strip().lower()] = val.strip()

    # Determine certificate type (ACME vs self-signed)
    fqdn = f"{HOSTNAME}.{DOMAIN}"
    acme_dir = Path("/etc/acme") / fqdn
    home_acme = Path.home() / ".acme.sh" / fqdn

    if acme_dir.exists() or home_acme.exists():
        info["type"] = "acme"
        info["auto_renew"] = True
    else:
        info["type"] = "selfsigned"
        info["auto_renew"] = False

    # Calculate days until expiration
    if "notafter" in info:
        import time
        try:
            # Parse date format: "Mar 22 10:30:00 2027 GMT"
            from datetime import datetime
            expires = datetime.strptime(info["notafter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expires - datetime.now()).days
            info["days_remaining"] = days_left
            if days_left < 0:
                info["status"] = "expired"
            elif days_left < 30:
                info["status"] = "expiring_soon"
            else:
                info["status"] = "valid"
        except Exception:
            info["status"] = "unknown"

    return info


@app.post("/ssl/setup", dependencies=[Depends(require_jwt)])
async def setup_ssl(background_tasks: BackgroundTasks):
    """Setup SSL certificate (self-signed)"""
    def do_setup():
        subprocess.run(["/usr/sbin/mailserverctl", "ssl", "selfsigned"],
                      stdout=open("/var/log/mail-ssl.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_setup)
    return {"success": True, "message": "Self-signed SSL setup started"}


# =============================================================================
# ACME CERTIFICATE MANAGEMENT
# =============================================================================

class AcmeIssueRequest(BaseModel):
    email: Optional[str] = None


@app.get("/acme/status", dependencies=[Depends(require_jwt)])
async def acme_status():
    """Get ACME certificate status"""
    fqdn = f"{HOSTNAME}.{DOMAIN}"
    acme_dir = Path("/etc/acme") / fqdn
    home_acme = Path.home() / ".acme.sh" / fqdn

    # Check if acme.sh is available
    acme_available = False
    success, out, _ = run_cmd(["which", "acme.sh"])
    if success:
        acme_available = True

    # Check for existing certificate
    cert_exists = False
    cert_info = {}
    if acme_dir.exists() or home_acme.exists():
        cert_exists = True
        cert_path = acme_dir / "fullchain.cer"
        if not cert_path.exists():
            cert_path = home_acme / "fullchain.cer"
        if cert_path.exists():
            success, out, _ = run_cmd(["openssl", "x509", "-in", str(cert_path),
                                       "-noout", "-subject", "-dates"])
            if success:
                for line in out.split("\n"):
                    if "=" in line:
                        key, val = line.split("=", 1)
                        cert_info[key.strip().lower()] = val.strip()

    return {
        "acme_available": acme_available,
        "certificate_exists": cert_exists,
        "domain": fqdn,
        "cert_info": cert_info,
    }


@app.post("/acme/issue", dependencies=[Depends(require_jwt)])
async def acme_issue(req: AcmeIssueRequest, background_tasks: BackgroundTasks):
    """Request ACME certificate from Let's Encrypt"""
    def do_issue():
        cmd = ["/usr/sbin/mailserverctl", "acme", "issue"]
        if req.email:
            cmd.append(req.email)
        subprocess.run(cmd,
                      stdout=open("/var/log/mail-acme.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_issue)
    return {"success": True, "message": "ACME certificate request started",
            "log": "/var/log/mail-acme.log"}


@app.post("/acme/renew", dependencies=[Depends(require_jwt)])
async def acme_renew(background_tasks: BackgroundTasks):
    """Renew ACME certificate"""
    def do_renew():
        subprocess.run(["/usr/sbin/mailserverctl", "acme", "renew"],
                      stdout=open("/var/log/mail-acme.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_renew)
    return {"success": True, "message": "ACME renewal started"}


@app.post("/acme/install", dependencies=[Depends(require_jwt)])
async def acme_install():
    """Install ACME certificate to mail server"""
    success, out, err = run_cmd(["/usr/sbin/mailserverctl", "acme", "install"])
    if success:
        return {"success": True, "message": "Certificate installed"}
    raise HTTPException(500, f"Failed: {err}")


# =============================================================================
# DNS SETUP
# =============================================================================

@app.get("/dns-setup", dependencies=[Depends(require_jwt)])
async def get_dns_records():
    """Get DNS records to configure"""
    fqdn = f"{HOSTNAME}.{DOMAIN}"
    return {
        "domain": DOMAIN,
        "records": [
            {"type": "MX", "name": DOMAIN, "value": f"10 {fqdn}.", "description": "Mail exchanger"},
            {"type": "A", "name": f"{HOSTNAME}.{DOMAIN}", "value": "<YOUR_IP>", "description": "Mail server IP"},
            {"type": "A", "name": f"webmail.{DOMAIN}", "value": "<YOUR_IP>", "description": "Webmail IP"},
            {"type": "TXT", "name": DOMAIN, "value": f"v=spf1 mx a:{fqdn} -all", "description": "SPF record"},
            {"type": "TXT", "name": f"_dmarc.{DOMAIN}", "value": f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{DOMAIN}", "description": "DMARC policy"},
        ],
        "note": "DKIM record requires key generation. Run: mailctl dkim-setup"
    }


# =============================================================================
# USER REPAIR
# =============================================================================

@app.post("/user/repair/{email}", dependencies=[Depends(require_jwt)])
async def repair_user_mailbox(email: str):
    """Repair user mailbox (doveadm force-resync)"""
    if not lxc_running(MAIL_CONTAINER):
        raise HTTPException(503, "Mail container not running")
    success, out, err = lxc_attach(MAIL_CONTAINER, f"doveadm force-resync -u '{email}' '*'")
    if success:
        return {"success": True, "message": f"Mailbox repaired for {email}"}
    raise HTTPException(500, f"Repair failed: {err}")


# =============================================================================
# FIX PORTS
# =============================================================================

@app.post("/fix-ports", dependencies=[Depends(require_jwt)])
async def fix_ports():
    """Check and fix mail server ports"""
    success, out, err = run_cmd(["/usr/sbin/mailctl", "fix-ports"])
    if success:
        return {"success": True, "output": out}
    raise HTTPException(500, f"Failed: {err}")


# =============================================================================
# SETTINGS
# =============================================================================

class SettingsUpdate(BaseModel):
    domain: Optional[str] = None
    hostname: Optional[str] = None
    # Canonical fields (Phase 1 rev. 2)
    lxc_ip: Optional[str] = None
    # Legacy aliases — accepted for back-compat, mapped to lxc_ip server-side.
    mail_ip: Optional[str] = None
    webmail_port: Optional[int] = None


@app.get("/settings", dependencies=[Depends(require_jwt)])
async def get_settings():
    """Get mail configuration settings."""
    return {
        "domain": DOMAIN,
        "hostname": HOSTNAME,
        # Canonical
        "container": CONTAINER,
        "lxc_ip": LXC_IP,
        "lxc_bridge": LXC_BRIDGE,
        "lxc_gateway": LXC_GATEWAY,
        "data_path": str(DATA_PATH),
        "lxc_path": str(LXC_PATH),
        # Legacy aliases (kept until v3.0)
        "mail_ip": LXC_IP,
        "webmail_port": WEBMAIL_PORT,
        "mail_container": CONTAINER,
        "webmail_container": CONTAINER,
    }


@app.post("/settings", dependencies=[Depends(require_jwt)])
async def update_settings(settings: SettingsUpdate):
    """Update mail configuration settings"""
    config_file = Path("/etc/secubox/mail.toml")

    # Read current config
    current = {}
    if config_file.exists():
        for line in config_file.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                key, val = line.split("=", 1)
                current[key.strip()] = val.strip().strip('"')

    # Update values. Canonical keys take precedence; legacy fields are
    # accepted for one release and mapped to canonical.
    if settings.domain:
        current["domain"] = settings.domain
    if settings.hostname:
        current["hostname"] = settings.hostname
    if settings.lxc_ip:
        current["lxc_ip"] = settings.lxc_ip
    elif settings.mail_ip:
        current["lxc_ip"] = settings.mail_ip
    if settings.webmail_port:
        # webmail_port is no longer meaningful (Roundcube is on :80 inside LXC,
        # proxied via host nginx :443). Recorded for audit only.
        current["webmail_port"] = str(settings.webmail_port)

    # Write config
    config_file.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# SecuBox Mail Configuration"]
    for key, val in current.items():
        if val.isdigit():
            lines.append(f'{key} = {val}')
        else:
            lines.append(f'{key} = "{val}"')
    config_file.write_text("\n".join(lines) + "\n")

    return {"success": True, "message": "Settings saved"}


# =============================================================================
# DKIM SETUP
# =============================================================================

# =============================================================================
# DKIM MANAGEMENT
# =============================================================================

@app.get("/av/status", dependencies=[Depends(require_jwt)])
async def av_status():
    """Get ClamAV antivirus status"""
    rootfs = LXC_PATH / MAIL_CONTAINER / "rootfs"

    status = {
        "installed": (rootfs / "usr/sbin/clamd").exists(),
        "configured": (rootfs / "etc/clamav/clamd.conf").exists(),
        "enabled": False,
        "running": False,
        "milter_running": False,
    }

    # Check if enabled in Postfix
    main_cf = rootfs / "etc/postfix/main.cf"
    if main_cf.exists():
        content = main_cf.read_text()
        status["enabled"] = "inet:localhost:8894" in content

    # Check if clamd and milter are running
    if lxc_running(MAIL_CONTAINER):
        success, out, _ = lxc_attach(MAIL_CONTAINER, "pgrep clamd")
        status["running"] = success
        success, out, _ = lxc_attach(MAIL_CONTAINER, "pgrep clamav-milter")
        status["milter_running"] = success

    # Check virus database
    db_file = rootfs / "var/lib/clamav/main.cvd"
    if db_file.exists():
        import datetime
        mtime = datetime.datetime.fromtimestamp(db_file.stat().st_mtime)
        status["database_updated"] = mtime.strftime("%Y-%m-%d %H:%M")
    else:
        db_file = rootfs / "var/lib/clamav/main.cld"
        if db_file.exists():
            import datetime
            mtime = datetime.datetime.fromtimestamp(db_file.stat().st_mtime)
            status["database_updated"] = mtime.strftime("%Y-%m-%d %H:%M")

    return status


@app.post("/av/setup", dependencies=[Depends(require_jwt)])
async def av_setup(background_tasks: BackgroundTasks):
    """Full ClamAV setup (install + configure + enable)"""
    def do_setup():
        subprocess.run(["/usr/sbin/mailserverctl", "av", "setup"],
                      stdout=open("/var/log/mail-av.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_setup)
    return {"success": True, "message": "ClamAV setup started (this may take several minutes)",
            "log": "/var/log/mail-av.log"}


@app.post("/av/enable", dependencies=[Depends(require_jwt)])
async def av_enable():
    """Enable ClamAV virus scanning"""
    success, out, err = run_cmd(["/usr/sbin/mailserverctl", "av", "enable"])
    if success:
        return {"success": True, "message": "ClamAV enabled"}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/av/disable", dependencies=[Depends(require_jwt)])
async def av_disable():
    """Disable ClamAV virus scanning"""
    success, out, err = run_cmd(["/usr/sbin/mailserverctl", "av", "disable"])
    if success:
        return {"success": True, "message": "ClamAV disabled"}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/av/update", dependencies=[Depends(require_jwt)])
async def av_update(background_tasks: BackgroundTasks):
    """Update ClamAV virus definitions"""
    def do_update():
        subprocess.run(["/usr/sbin/mailserverctl", "av", "update"],
                      stdout=open("/var/log/mail-av-update.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_update)
    return {"success": True, "message": "ClamAV virus database update started"}
