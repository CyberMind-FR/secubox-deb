"""SecuBox MetaBlogizer API - Static Site Publisher

Three-fold perspective:
1. Components: Nginx runtime + Tor optional
2. Status: Site count, published sites
3. Access: Site URLs and domains

SecuBox is an appliance and network model - distributed peer applications.
"""
import subprocess
import os
import json
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, UploadFile, File
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox MetaBlogizer", version="1.0.0")
config = get_config("metablogizer")

SITES_ROOT = Path(config.get("sites_root", "/srv/metablogizer/sites") if config else "/srv/metablogizer/sites")
DATA_PATH = Path(config.get("data_path", "/srv/metablogizer") if config else "/srv/metablogizer")
NGINX_VHOST_DIR = Path("/etc/nginx/sites-available")
NGINX_ENABLED_DIR = Path("/etc/nginx/sites-enabled")


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


def load_sites() -> List[dict]:
    """Load all sites from directory"""
    sites = []
    if not SITES_ROOT.exists():
        return sites

    for site_dir in SITES_ROOT.iterdir():
        if not site_dir.is_dir() or site_dir.name.startswith("."):
            continue

        name = site_dir.name
        domain = f"{name}.local"
        published = False

        # Read site config
        config_file = site_dir / "site.json"
        if config_file.exists():
            try:
                cfg = json.loads(config_file.read_text())
                domain = cfg.get("domain", domain)
            except:
                pass

        # Check if published
        published = (NGINX_ENABLED_DIR / f"{name}.conf").exists()

        # Get size
        size = "0"
        success, out, _ = run_cmd(["du", "-sh", str(site_dir)])
        if success:
            size = out.split()[0]

        sites.append({
            "name": name,
            "domain": domain,
            "published": published,
            "directory": str(site_dir),
            "size": size,
        })

    return sites


# =============================================================================
# STATUS - Module state and health
# =============================================================================

@app.get("/status")
async def status():
    """Get unified MetaBlogizer status (public endpoint)"""
    sites = load_sites()
    published = sum(1 for s in sites if s.get("published"))

    return {
        "module": "metablogizer",
        "version": "1.0.0",
        "enabled": config.get("enabled", True) if config else True,
        "components": {
            "nginx": {
                "name": "nginx",
                "installed": True,
                "running": nginx_running(),
            }
        },
        "site_count": len(sites),
        "published_count": published,
        "sites_root": str(SITES_ROOT),
        "running": nginx_running(),
        "installed": True,
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "ok" if nginx_running() else "degraded",
        "nginx": "ok" if nginx_running() else "down",
    }


# =============================================================================
# ACCESS - Sites list and URLs
# =============================================================================

@app.get("/access")
async def get_access():
    """Get all sites with their access URLs (public)"""
    sites = load_sites()
    return {
        "sites": [
            {
                "name": s["name"],
                "domain": s["domain"],
                "url": f"http://{s['domain']}",
                "published": s["published"],
            }
            for s in sites
        ],
        "count": len(sites),
    }


# =============================================================================
# SITES MANAGEMENT
# =============================================================================

class SiteCreate(BaseModel):
    name: str
    domain: Optional[str] = None
    template: str = "default"


class SiteUpdate(BaseModel):
    domain: Optional[str] = None
    enabled: Optional[bool] = None


@app.get("/sites", dependencies=[Depends(require_jwt)])
async def list_sites():
    """List all sites"""
    return {"sites": load_sites(), "count": len(load_sites())}


@app.get("/site/{name}", dependencies=[Depends(require_jwt)])
async def get_site(name: str):
    """Get site details"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    domain = f"{name}.local"
    config_file = site_dir / "site.json"
    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            domain = cfg.get("domain", domain)
        except:
            pass

    # List files
    files = []
    public_dir = site_dir / "public"
    scan_dir = public_dir if public_dir.exists() else site_dir
    for f in scan_dir.rglob("*"):
        if f.is_file():
            files.append(str(f.relative_to(scan_dir)))

    published = (NGINX_ENABLED_DIR / f"{name}.conf").exists()

    return {
        "name": name,
        "domain": domain,
        "directory": str(site_dir),
        "files": files[:100],
        "published": published,
    }


@app.post("/site", dependencies=[Depends(require_jwt)])
async def create_site(site: SiteCreate):
    """Create a new site"""
    SITES_ROOT.mkdir(parents=True, exist_ok=True)
    site_dir = SITES_ROOT / site.name

    if site_dir.exists():
        raise HTTPException(400, "Site already exists")

    domain = site.domain or f"{site.name}.local"

    # Create site
    public_dir = site_dir / "public"
    public_dir.mkdir(parents=True)

    # Create default index
    (public_dir / "index.html").write_text(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{site.name}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
        .container {{ text-align: center; }}
        h1 {{ color: #58a6ff; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{site.name}</h1>
        <p>Your static site is ready!</p>
    </div>
</body>
</html>
""")

    # Save config
    (site_dir / "site.json").write_text(json.dumps({
        "name": site.name,
        "domain": domain,
        "template": site.template,
    }, indent=2))

    return {"success": True, "name": site.name, "domain": domain}


@app.delete("/site/{name}", dependencies=[Depends(require_jwt)])
async def delete_site(name: str):
    """Delete a site"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Unpublish first
    (NGINX_ENABLED_DIR / f"{name}.conf").unlink(missing_ok=True)
    (NGINX_VHOST_DIR / f"{name}.conf").unlink(missing_ok=True)

    # Delete directory
    shutil.rmtree(site_dir)

    return {"success": True, "name": name}


# =============================================================================
# PUBLISHING
# =============================================================================

@app.post("/site/{name}/publish", dependencies=[Depends(require_jwt)])
async def publish_site(name: str):
    """Publish a site (create nginx vhost)"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    domain = f"{name}.local"
    config_file = site_dir / "site.json"
    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            domain = cfg.get("domain", domain)
        except:
            pass

    public_dir = site_dir / "public"
    root_dir = str(public_dir) if public_dir.exists() else str(site_dir)

    # Generate nginx config
    nginx_conf = f"""# MetaBlogizer site: {name}
# Generated by SecuBox MetaBlogizer

server {{
    listen 80;
    server_name {domain};
    root {root_dir};
    index index.html index.htm;

    location / {{
        try_files $uri $uri/ =404;
    }}

    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {{
        expires 1y;
        add_header Cache-Control "public, immutable";
    }}

    access_log /var/log/nginx/{name}_access.log;
    error_log /var/log/nginx/{name}_error.log;
}}
"""

    NGINX_VHOST_DIR.mkdir(parents=True, exist_ok=True)
    (NGINX_VHOST_DIR / f"{name}.conf").write_text(nginx_conf)

    # Enable
    link = NGINX_ENABLED_DIR / f"{name}.conf"
    if not link.exists():
        link.symlink_to(NGINX_VHOST_DIR / f"{name}.conf")

    # Reload nginx
    run_cmd(["nginx", "-t"])
    run_cmd(["systemctl", "reload", "nginx"])

    return {"success": True, "name": name, "domain": domain, "url": f"http://{domain}"}


@app.post("/site/{name}/unpublish", dependencies=[Depends(require_jwt)])
async def unpublish_site(name: str):
    """Unpublish a site"""
    (NGINX_ENABLED_DIR / f"{name}.conf").unlink(missing_ok=True)
    run_cmd(["systemctl", "reload", "nginx"])

    return {"success": True, "name": name}


@app.post("/site/{name}/upload", dependencies=[Depends(require_jwt)])
async def upload_content(name: str, file: UploadFile = File(...)):
    """Upload content to a site (zip/tar.gz)"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        site_dir.mkdir(parents=True)

    public_dir = site_dir / "public"
    public_dir.mkdir(exist_ok=True)

    content = await file.read()
    temp_file = site_dir / f"_upload_{file.filename}"
    temp_file.write_bytes(content)

    try:
        if file.filename.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(temp_file, 'r') as zf:
                zf.extractall(public_dir)
        elif file.filename.endswith((".tar.gz", ".tgz")):
            import tarfile
            with tarfile.open(temp_file, 'r:gz') as tf:
                tf.extractall(public_dir)
        else:
            raise HTTPException(400, "Unsupported format. Use .zip or .tar.gz")

        temp_file.unlink()
    except Exception as e:
        temp_file.unlink(missing_ok=True)
        raise HTTPException(400, f"Failed to extract: {e}")

    return {"success": True, "name": name}


# =============================================================================
# MIGRATION
# =============================================================================

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"


@app.post("/migrate", dependencies=[Depends(require_jwt)])
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks):
    """Migrate MetaBlogizer data from OpenWrt source"""
    def do_migrate():
        subprocess.run(["/usr/sbin/metablogizerctl", "migrate", req.source],
                      stdout=open("/var/log/metablogizer-migrate.log", "w"),
                      stderr=subprocess.STDOUT)

    background_tasks.add_task(do_migrate)
    return {"success": True, "message": f"Migration from {req.source} started"}


# =============================================================================
# LOGS & QR
# =============================================================================

@app.get("/logs/{name}", dependencies=[Depends(require_jwt)])
async def get_logs(name: str, lines: int = 100):
    """Get access logs for a site"""
    log_file = Path(f"/var/log/nginx/{name}_access.log")
    logs = []

    if log_file.exists():
        success, out, _ = run_cmd(["tail", f"-n{lines}", str(log_file)])
        if success:
            logs = out.split("\n")

    return {"name": name, "logs": logs}


@app.get("/site/{name}/qrcode", dependencies=[Depends(require_jwt)])
async def get_qrcode(name: str):
    """Generate QR code for site URL"""
    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    domain = f"{name}.local"
    config_file = site_dir / "site.json"
    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            domain = cfg.get("domain", domain)
        except:
            pass

    url = f"http://{domain}"

    try:
        import qrcode
        import base64
        from io import BytesIO

        qr = qrcode.make(url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        b64 = base64.b64encode(buffer.getvalue()).decode()

        return {"qrcode": f"data:image/png;base64,{b64}", "url": url}
    except ImportError:
        return {"url": url, "error": "qrcode module not installed"}
