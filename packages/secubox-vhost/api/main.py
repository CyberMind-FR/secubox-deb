"""SecuBox VHost API - Nginx Virtual Host Management

Three-fold perspective:
1. Components: Nginx server + ACME certificates
2. Status: Running state, vhost count, certificates
3. Access: Configured domains and their backends

SecuBox is an appliance and network model - distributed peer applications.
"""
import subprocess
import os
import json
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config
from api.exposure_read import read_exposure
from api.exposure_seed import ensure_snippet

app = FastAPI(title="SecuBox VHost", version="1.1.0")
config = get_config("vhost")

NGINX_VHOST_DIR = Path(config.get("nginx_vhost_dir", "/etc/nginx/sites-available") if config else "/etc/nginx/sites-available")
NGINX_ENABLED_DIR = Path(config.get("nginx_enabled_dir", "/etc/nginx/sites-enabled") if config else "/etc/nginx/sites-enabled")
ACME_DIR = Path(config.get("acme_dir", "/etc/acme") if config else "/etc/acme")
DATA_PATH = Path(config.get("data_path", "/srv/vhost") if config else "/srv/vhost")


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def nginx_running() -> bool:
    """Check if nginx is running"""
    success, _, _ = run_cmd(["pgrep", "nginx"])
    return success


def get_nginx_version() -> str:
    """Get nginx version"""
    success, _, err = run_cmd(["nginx", "-v"])
    if err:
        import re
        match = re.search(r'nginx/(\d+\.\d+\.\d+)', err)
        if match:
            return match.group(1)
    return "unknown"


def acme_available() -> bool:
    """Check if acme.sh is available"""
    success, _, _ = run_cmd(["which", "acme.sh"])
    return success


# =============================================================================
# STATUS - Module state and health
# =============================================================================

@app.get("/status")
async def status():
    """Get unified VHost status (public endpoint)"""
    running = nginx_running()

    # Count vhosts
    vhost_count = 0
    enabled_count = 0
    if NGINX_VHOST_DIR.exists():
        vhost_count = len(list(NGINX_VHOST_DIR.glob("*.conf")))
    if NGINX_ENABLED_DIR.exists():
        enabled_count = len([f for f in NGINX_ENABLED_DIR.glob("*.conf") if f.is_symlink() or f.is_file()])

    # Count certificates
    cert_count = 0
    if ACME_DIR.exists():
        cert_count = len([d for d in ACME_DIR.iterdir() if d.is_dir() and (d / "fullchain.cer").exists()])

    return {
        "module": "vhost",
        "version": "1.0.0",
        "enabled": config.get("enabled", True) if config else True,
        "components": {
            "nginx": {
                "name": "nginx",
                "installed": True,
                "running": running,
                "version": get_nginx_version() if running else None,
            },
            "acme": {
                "name": "acme.sh",
                "installed": acme_available(),
                "running": True,
            }
        },
        "vhost_count": vhost_count,
        "enabled_count": enabled_count,
        "cert_count": cert_count,
        "running": running,
        "installed": True,
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    running = nginx_running()
    return {
        "status": "ok" if running else "degraded",
        "nginx": "ok" if running else "down",
    }


# =============================================================================
# COMPONENTS - Three-fold architecture (What)
# =============================================================================

@app.get("/components")
async def get_components():
    """List system components (public, three-fold: what)"""
    running = nginx_running()
    acme = acme_available()

    vhost_count = 0
    if NGINX_VHOST_DIR.exists():
        vhost_count = len(list(NGINX_VHOST_DIR.glob("*.conf")))

    cert_count = 0
    if ACME_DIR.exists():
        cert_count = len([d for d in ACME_DIR.iterdir() if d.is_dir() and (d / "fullchain.cer").exists()])

    return {
        "components": [
            {
                "name": "Nginx Web Server",
                "type": "service",
                "description": "HTTP/HTTPS reverse proxy",
                "installed": True,
                "running": running,
                "version": get_nginx_version() if running else None,
            },
            {
                "name": "ACME Client",
                "type": "tool",
                "description": "Let's Encrypt certificate automation",
                "installed": acme,
                "running": False,
            },
            {
                "name": "VHost Configs",
                "type": "config",
                "path": str(NGINX_VHOST_DIR),
                "description": "Virtual host configurations",
                "count": vhost_count,
            },
            {
                "name": "SSL Certificates",
                "type": "certs",
                "path": str(ACME_DIR),
                "description": "Let's Encrypt certificates",
                "count": cert_count,
            },
        ]
    }


# =============================================================================
# ACCESS - VHosts list and connection info
# =============================================================================

@app.get("/access")
async def get_access():
    """Get all vhosts with their access URLs (public)"""
    vhosts = []

    if NGINX_VHOST_DIR.exists():
        for conf_file in NGINX_VHOST_DIR.glob("*.conf"):
            if conf_file.name.startswith("_") or conf_file.name == "default.conf":
                continue
            domain = conf_file.stem
            enabled = (NGINX_ENABLED_DIR / conf_file.name).exists()

            # Parse config for backend
            backend = ""
            ssl = False
            try:
                content = conf_file.read_text()
                for line in content.split("\n"):
                    if "proxy_pass" in line:
                        backend = line.split()[-1].rstrip(";")
                        break
                ssl = "listen 443" in content or "ssl_certificate" in content
            except:
                pass

            vhosts.append({
                "domain": domain,
                "url": f"https://{domain}" if ssl else f"http://{domain}",
                "backend": backend,
                "ssl": ssl,
                "enabled": enabled,
            })

    return {"vhosts": vhosts, "count": len(vhosts)}


# =============================================================================
# VHOSTS MANAGEMENT
# =============================================================================

class VHostCreate(BaseModel):
    domain: str
    backend: str = ""            # not required for a pure redirect vhost
    tls_mode: str = "off"  # off, acme, manual
    websocket: bool = False
    auth: bool = False
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None
    ssl_redirect: bool = True
    redirect_to: Optional[str] = None   # e.g. "https://example.com" → 301 redirect vhost


class VHostUpdate(BaseModel):
    backend: Optional[str] = None
    tls_mode: Optional[str] = None
    websocket: Optional[bool] = None
    auth: Optional[bool] = None
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None
    enabled: Optional[bool] = None


HAPROXY_ROUTES_FILE = Path("/srv/mitmproxy/haproxy-routes.json")
HAPROXY_CERTS_DIR = Path("/data/haproxy/certs")


def _is_public_fqdn(name: str) -> bool:
    name = (name or "").strip().rstrip(";")
    if not name or name in ("_", "localhost") or name.endswith(".local"):
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name):
        return False
    return "." in name


def _server_name_fqdn(content: str):
    """First public FQDN from any server_name directive (skips _, localhost, IPs)."""
    for line in content.split("\n"):
        s = line.strip()
        if s.startswith("server_name"):
            for tok in s[len("server_name"):].strip().rstrip(";").split():
                if _is_public_fqdn(tok):
                    return tok
    return None


def _load_haproxy_routes() -> dict:
    """Public FQDN -> backend target from the HAProxy/mitmproxy route map."""
    try:
        d = json.loads(HAPROXY_ROUTES_FILE.read_text())
        return {k: v for k, v in d.items() if _is_public_fqdn(k)}
    except Exception:
        return {}


@app.get("/vhosts", dependencies=[Depends(require_jwt)])
async def list_vhosts():
    """List all virtual hosts with full, clickable public URLs.

    Public vhosts are HAProxy-fronted (TLS terminated there), so the real domain
    is the nginx server_name FQDN — NOT the config filename. We fall back to the
    HAProxy route map for backends whose nginx config only has local names, and
    append HAProxy public routes that have no nginx config, so the list is the
    COMPLETE set of reachable vhosts with working https:// links.
    """
    vhosts = []
    routes = _load_haproxy_routes()
    seen = set()

    if NGINX_VHOST_DIR.exists():
        for conf_file in sorted(NGINX_VHOST_DIR.glob("*.conf")):
            if conf_file.name.startswith("_") or conf_file.name == "default.conf":
                continue
            stem = conf_file.stem
            enabled = (NGINX_ENABLED_DIR / conf_file.name).exists()
            backend = ""
            websocket = False
            content = ""
            try:
                content = conf_file.read_text()
                for line in content.split("\n"):
                    if "proxy_pass" in line:
                        backend = line.split()[-1].rstrip(";")
                    if "Upgrade" in line:
                        websocket = True
            except Exception:
                pass

            domain = _server_name_fqdn(content)
            if not domain:
                domain = next((k for k in routes if k.split(".")[0] == stem), None) or stem

            is_public = _is_public_fqdn(domain)
            ssl = is_public  # HAProxy terminates TLS for every public vhost
            url = f"https://{domain}" if is_public else None
            tls_mode = "haproxy" if is_public else "off"

            cert_expires = None
            if is_public:
                cert_path = HAPROXY_CERTS_DIR / f"{domain}.pem"
                if cert_path.exists():
                    success, out, _ = run_cmd(
                        ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"])
                    if success:
                        cert_expires = out.split("=")[-1].strip()

            seen.add(domain)
            vhosts.append({
                "domain": domain,
                "backend": backend,
                "tls_mode": tls_mode,
                "ssl": ssl,
                "websocket": websocket,
                "enabled": enabled,
                "cert_expires": cert_expires,
                "url": url,
                "source": "nginx",
                "config_file": str(conf_file),
                "exposure": read_exposure(domain),
            })

    # Append HAProxy public vhosts with no nginx config (complete the list).
    for domain, target in routes.items():
        if domain in seen:
            continue
        seen.add(domain)
        try:
            backend = f"{target[0]}:{target[1]}" if isinstance(target, (list, tuple)) else str(target)
        except Exception:
            backend = ""
        vhosts.append({
            "domain": domain,
            "backend": backend,
            "tls_mode": "haproxy",
            "ssl": True,
            "websocket": False,
            "enabled": True,
            "cert_expires": None,
            "url": f"https://{domain}",
            "source": "haproxy",
            "config_file": None,
            "exposure": read_exposure(domain),
        })

    vhosts.sort(key=lambda v: v["domain"])
    return {"vhosts": vhosts, "count": len(vhosts)}


@app.get("/vhost/{domain}", dependencies=[Depends(require_jwt)])
async def get_vhost(domain: str):
    """Get single vhost details"""
    conf_file = NGINX_VHOST_DIR / f"{domain}.conf"
    if not conf_file.exists():
        raise HTTPException(404, "VHost not found")

    enabled = (NGINX_ENABLED_DIR / f"{domain}.conf").exists()

    # Parse config
    backend = ""
    tls_mode = "off"
    websocket = False
    ssl = False
    config_content = ""

    try:
        content = conf_file.read_text()
        config_content = content
        for line in content.split("\n"):
            if "proxy_pass" in line:
                backend = line.split()[-1].rstrip(";")
            if "Upgrade" in line:
                websocket = True
        ssl = "listen 443" in content or "ssl_certificate" in content
        if ssl:
            tls_mode = "acme" if "/etc/acme/" in content else "manual"
    except:
        pass

    # Certificate info
    cert_info = {}
    if ssl:
        cert_path = ACME_DIR / domain / "fullchain.cer"
        if cert_path.exists():
            success, out, _ = run_cmd([
                "openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-dates", "-issuer"
            ])
            if success:
                for line in out.split("\n"):
                    if "=" in line:
                        key, val = line.split("=", 1)
                        cert_info[key.strip().lower()] = val.strip()

    return {
        "domain": domain,
        "backend": backend,
        "tls_mode": tls_mode,
        "ssl": ssl,
        "websocket": websocket,
        "enabled": enabled,
        "cert_info": cert_info if cert_info else None,
        "config_content": config_content,
    }


def generate_vhost_config(domain: str, backend: str, tls_mode: str, websocket: bool,
                           ssl_redirect: bool = True, exposure_include: bool = False,
                           redirect_to: str = "") -> str:
    """Generate nginx vhost configuration.

    When redirect_to is set, the vhost is a pure 301 redirect (no backend proxy,
    no exposure gate) — e.g. www.example.com → https://example.com.
    """
    conf = f"""# VHost for {domain}
# Generated by SecuBox VHost Manager

server {{
    listen 80;
    server_name {domain};
"""

    ssl_active = False
    cert_path = ""
    key_path = ""

    if tls_mode == "acme":
        cert_path = f"{ACME_DIR}/{domain}/fullchain.cer"
        key_path = f"{ACME_DIR}/{domain}/{domain}.key"
        if Path(cert_path).exists() and Path(key_path).exists():
            ssl_active = True
    elif tls_mode == "manual":
        cert_path = f"{DATA_PATH}/ssl/{domain}/fullchain.pem"
        key_path = f"{DATA_PATH}/ssl/{domain}/privkey.pem"
        if Path(cert_path).exists() and Path(key_path).exists():
            ssl_active = True

    if ssl_active and ssl_redirect:
        conf += f"""    location /.well-known/acme-challenge/ {{ root /var/www/acme; }}
    location / {{ return 301 https://$host$request_uri; }}
}}

server {{
    listen 443 ssl http2;
    server_name {domain};
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
"""

    conf += "\n    location / {\n"
    if redirect_to:
        # Pure 301 redirect vhost (no backend). $request_uri preserves path+query.
        conf += f"        return 301 {redirect_to}$request_uri;\n"
    else:
        if exposure_include:
            # Seeded by ensure_snippet() at create time (Fix 3, ref #793) — only emitted
            # when seeding succeeded, so nginx never references a missing include.
            conf += f"        include /etc/nginx/snippets/exposure/{domain}.conf;\n"
        conf += f"        proxy_pass {backend};\n"
        conf += "        proxy_http_version 1.1;\n"
        conf += "        proxy_set_header Host $host;\n"
        conf += "        proxy_set_header X-Real-IP $remote_addr;\n"
        conf += "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        conf += "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        if websocket:
            conf += "        proxy_set_header Upgrade $http_upgrade;\n"
            conf += '        proxy_set_header Connection "upgrade";\n'
        conf += "        proxy_connect_timeout 60s;\n"
        conf += "        proxy_send_timeout 60s;\n"
        conf += "        proxy_read_timeout 60s;\n"
    conf += "    }\n"
    conf += f"    access_log /var/log/nginx/{domain}_access.log;\n"
    conf += f"    error_log /var/log/nginx/{domain}_error.log;\n"
    conf += "}\n"

    return conf


@app.post("/vhost", dependencies=[Depends(require_jwt)])
async def create_vhost(vhost: VHostCreate):
    """Create a new virtual host"""
    NGINX_VHOST_DIR.mkdir(parents=True, exist_ok=True)

    conf_file = NGINX_VHOST_DIR / f"{vhost.domain}.conf"
    if conf_file.exists():
        raise HTTPException(400, "VHost already exists")

    redirect_to = (vhost.redirect_to or "").strip()
    if not redirect_to and not vhost.backend:
        raise HTTPException(400, "backend required unless redirect_to is set")

    # A pure redirect vhost has no proxy/gate → no snippet to seed. Otherwise seed
    # the exposure snippet FIRST; only include it if seeding succeeded — nginx must
    # never reload with an include pointing at a file that may not exist (ref #793
    # Fix 3). A failed seed leaves the vhost ungated but loadable.
    seeded = False
    if not redirect_to:
        seeded = ensure_snippet(vhost.domain)
        if not seeded:
            import logging
            logging.getLogger(__name__).warning(
                "exposure snippet seed failed for %s; vhost created ungated", vhost.domain)

    # Generate config
    conf_content = generate_vhost_config(
        vhost.domain, vhost.backend, vhost.tls_mode,
        vhost.websocket, vhost.ssl_redirect, exposure_include=seeded,
        redirect_to=redirect_to
    )
    conf_file.write_text(conf_content)

    # Enable vhost
    enabled_link = NGINX_ENABLED_DIR / f"{vhost.domain}.conf"
    if not enabled_link.exists():
        enabled_link.symlink_to(conf_file)

    return {"success": True, "message": f"VHost {vhost.domain} created", "reload_required": True}


@app.put("/vhost/{domain}", dependencies=[Depends(require_jwt)])
async def update_vhost(domain: str, update: VHostUpdate):
    """Update an existing virtual host"""
    conf_file = NGINX_VHOST_DIR / f"{domain}.conf"
    if not conf_file.exists():
        raise HTTPException(404, "VHost not found")

    # Get current config
    current = await get_vhost(domain)

    backend = update.backend or current["backend"]
    tls_mode = update.tls_mode or current["tls_mode"]
    websocket = update.websocket if update.websocket is not None else current["websocket"]

    # Re-seed (idempotent, never overwrites an existing snippet) and re-wire the
    # exposure include exactly like create_vhost — otherwise regenerating the
    # config here would silently drop the include line for a previously-gated
    # vhost while the on-disk snippet still restricts it (ref #793 Fix B).
    seeded = ensure_snippet(domain)

    # Regenerate config
    conf_content = generate_vhost_config(domain, backend, tls_mode, websocket,
                                          exposure_include=seeded)
    conf_file.write_text(conf_content)

    # Handle enable/disable
    enabled_link = NGINX_ENABLED_DIR / f"{domain}.conf"
    if update.enabled is not None:
        if update.enabled and not enabled_link.exists():
            enabled_link.symlink_to(conf_file)
        elif not update.enabled and enabled_link.exists():
            enabled_link.unlink()

    return {"success": True, "message": f"VHost {domain} updated", "reload_required": True}


@app.delete("/vhost/{domain}", dependencies=[Depends(require_jwt)])
async def delete_vhost(domain: str):
    """Delete a virtual host"""
    conf_file = NGINX_VHOST_DIR / f"{domain}.conf"
    enabled_link = NGINX_ENABLED_DIR / f"{domain}.conf"

    if enabled_link.exists():
        enabled_link.unlink()
    if conf_file.exists():
        conf_file.unlink()

    return {"success": True, "message": f"VHost {domain} deleted", "reload_required": True}


# =============================================================================
# CERTIFICATES
# =============================================================================

@app.get("/certificates")
async def list_certificates():
    """List all certificates (public)"""
    certs = []

    if ACME_DIR.exists():
        for cert_dir in ACME_DIR.iterdir():
            if not cert_dir.is_dir():
                continue
            cert_file = cert_dir / "fullchain.cer"
            if not cert_file.exists():
                continue

            domain = cert_dir.name
            expires = ""
            issuer = ""

            success, out, _ = run_cmd([
                "openssl", "x509", "-in", str(cert_file), "-noout", "-enddate", "-issuer"
            ])
            if success:
                for line in out.split("\n"):
                    if "notAfter" in line:
                        expires = line.split("=")[-1]
                    if "issuer" in line.lower():
                        issuer = line.split("=", 1)[-1]

            certs.append({
                "domain": domain,
                "expires": expires,
                "issuer": issuer,
                "cert_file": str(cert_file),
            })

    return {"certificates": certs, "count": len(certs)}


class CertRequest(BaseModel):
    domain: str
    email: str


@app.post("/certificate/issue", dependencies=[Depends(require_jwt)])
async def request_certificate(req: CertRequest, background_tasks: BackgroundTasks):
    """Request a Let's Encrypt certificate"""
    if not acme_available():
        raise HTTPException(400, "acme.sh not installed")

    def do_request():
        subprocess.run([
            "acme.sh", "--issue", "-d", req.domain,
            "--webroot", "/var/www/acme", "--accountemail", req.email
        ], stdout=open("/var/log/vhost-cert.log", "w"), stderr=subprocess.STDOUT)

    background_tasks.add_task(do_request)
    return {"success": True, "message": f"Certificate request started for {req.domain}"}


# =============================================================================
# SERVICE CONTROL
# =============================================================================

@app.post("/reload", dependencies=[Depends(require_jwt)])
async def reload_nginx():
    """Reload nginx configuration"""
    # Test config first
    success, _, err = run_cmd(["nginx", "-t"])
    if not success:
        raise HTTPException(400, f"Invalid config: {err}")

    success, _, err = run_cmd(["systemctl", "reload", "nginx"])
    if success:
        return {"success": True, "message": "Nginx reloaded"}
    raise HTTPException(500, f"Reload failed: {err}")


@app.post("/test", dependencies=[Depends(require_jwt)])
async def test_config():
    """Test nginx configuration"""
    success, out, err = run_cmd(["nginx", "-t"])
    return {
        "valid": success,
        "message": "Configuration is valid" if success else f"Invalid: {err}"
    }


# =============================================================================
# MIGRATION
# =============================================================================

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"


@app.post("/migrate", dependencies=[Depends(require_jwt)])
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks):
    """Migrate VHosts from OpenWrt source"""
    def do_migrate():
        subprocess.run(["/usr/sbin/vhostctl", "migrate", req.source],
                      stdout=open("/var/log/vhost-migrate.log", "w"),
                      stderr=subprocess.STDOUT)

    background_tasks.add_task(do_migrate)
    return {"success": True, "message": f"Migration from {req.source} started"}


# =============================================================================
# LOGS
# =============================================================================

@app.get("/logs/{domain}", dependencies=[Depends(require_jwt)])
async def get_access_logs(domain: str, lines: int = 100):
    """Get access logs for a domain"""
    log_file = Path(f"/var/log/nginx/{domain}_access.log")
    logs = []

    if log_file.exists():
        success, out, _ = run_cmd(["tail", f"-n{lines}", str(log_file)])
        if success:
            logs = out.split("\n")

    return {"domain": domain, "logs": logs}
