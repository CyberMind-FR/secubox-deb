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
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import Response
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Mail", version="1.6.0")
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
                "running": lxc_running(MAIL_CONTAINER),
                "ports": [25, 587, 465, 143, 993, 110, 995],
                "ip": MAIL_IP,
            },
            {
                "name": "Webmail",
                "type": "lxc",
                "container": WEBMAIL_CONTAINER,
                "description": "Roundcube webmail interface",
                "installed": lxc_exists(WEBMAIL_CONTAINER),
                "running": lxc_running(WEBMAIL_CONTAINER),
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
    mail_ip: Optional[str] = None
    webmail_port: Optional[int] = None


@app.get("/settings", dependencies=[Depends(require_jwt)])
async def get_settings():
    """Get mail configuration settings"""
    return {
        "domain": DOMAIN,
        "hostname": HOSTNAME,
        "mail_ip": MAIL_IP,
        "webmail_port": WEBMAIL_PORT,
        "mail_container": MAIL_CONTAINER,
        "webmail_container": WEBMAIL_CONTAINER,
        "data_path": str(DATA_PATH),
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

    # Update values
    if settings.domain:
        current["domain"] = settings.domain
    if settings.hostname:
        current["hostname"] = settings.hostname
    if settings.mail_ip:
        current["mail_ip"] = settings.mail_ip
    if settings.webmail_port:
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

@app.get("/dkim/status", dependencies=[Depends(require_jwt)])
async def dkim_status():
    """Get DKIM status"""
    private_key = DATA_PATH / "dkim" / "default.private"
    dns_record = DATA_PATH / "dkim" / "default.txt"

    status = {
        "key_exists": private_key.exists(),
        "dns_record_exists": dns_record.exists(),
        "domain": DOMAIN,
        "selector": "default",
    }

    # Get DNS record content
    if dns_record.exists():
        status["dns_record"] = dns_record.read_text().strip()

    # Check OpenDKIM service in container
    if lxc_running(MAIL_CONTAINER):
        success, out, _ = lxc_attach(MAIL_CONTAINER, "pgrep opendkim")
        status["opendkim_running"] = success

        # Check milter config
        success, out, _ = lxc_attach(MAIL_CONTAINER, "grep -q smtpd_milters /etc/postfix/main.cf")
        status["milter_configured"] = success
    else:
        status["opendkim_running"] = False
        status["milter_configured"] = False

    return status


@app.post("/dkim/setup", dependencies=[Depends(require_jwt)])
async def setup_dkim(background_tasks: BackgroundTasks):
    """Full DKIM setup (keygen + OpenDKIM install + configure)"""
    def do_setup():
        subprocess.run(["/usr/sbin/mailserverctl", "dkim", "setup"],
                      stdout=open("/var/log/mail-dkim.log", "w"),
                      stderr=subprocess.STDOUT)
    background_tasks.add_task(do_setup)
    return {"success": True, "message": "DKIM setup started", "log": "/var/log/mail-dkim.log"}


@app.post("/dkim/keygen", dependencies=[Depends(require_jwt)])
async def dkim_keygen():
    """Generate DKIM keys only"""
    success, out, err = run_cmd(["/usr/sbin/mailserverctl", "dkim", "keygen"])
    if success:
        # Get the DNS record
        dns_file = DATA_PATH / "dkim" / "default.txt"
        dns_record = dns_file.read_text().strip() if dns_file.exists() else ""
        return {"success": True, "message": "DKIM keys generated", "dns_record": dns_record}
    raise HTTPException(500, f"Failed: {err}")


@app.post("/dkim/sync", dependencies=[Depends(require_jwt)])
async def dkim_sync():
    """Sync DKIM keys to container"""
    success, out, err = run_cmd(["/usr/sbin/mailserverctl", "dkim", "sync"])
    if success:
        return {"success": True, "message": "DKIM keys synced to container"}
    raise HTTPException(500, f"Failed: {err}")


@app.get("/dkim/record", dependencies=[Depends(require_jwt)])
async def get_dkim_record():
    """Get DKIM DNS record"""
    dns_file = DATA_PATH / "dkim" / "default.txt"
    bind_file = DATA_PATH / "dkim" / "default.bind"

    if not dns_file.exists():
        return {"exists": False}

    result = {
        "exists": True,
        "selector": "default",
        "domain": DOMAIN,
        "record": dns_file.read_text().strip(),
    }

    if bind_file.exists():
        result["bind_format"] = bind_file.read_text().strip()

    return result
