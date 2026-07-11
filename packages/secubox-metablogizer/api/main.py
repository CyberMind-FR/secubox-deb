"""SecuBox MetaBlogizer API - Static Site Publisher

Three-fold perspective:
1. Components: Nginx runtime + Tor optional
2. Status: Site count, published sites
3. Access: Site URLs and domains

SecuBox is an appliance and network model - distributed peer applications.
"""
import subprocess
import os
import sys
import json
import shutil
from pathlib import Path

# Self-bootstrap api/ onto sys.path so `from site_schema import …` and
# `from rmtree import …` resolve under `uvicorn api.main:app` (where only
# the parent dir is auto-added). Tests use PYTHONPATH=api so the
# insert is a no-op in that path. See #109.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, UploadFile, File, Request
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox MetaBlogizer", version="1.2.0")
config = get_config("metablogizer")

SITES_ROOT = Path(config.get("sites_root", "/srv/metablogizer/sites") if config else "/srv/metablogizer/sites")
AUTO_PUBLISH = config.get("auto_publish", True) if config else True
DATA_PATH = Path(config.get("data_path", "/srv/metablogizer") if config else "/srv/metablogizer")
NGINX_VHOST_DIR = Path("/etc/nginx/sites-available")
NGINX_ENABLED_DIR = Path("/etc/nginx/sites-enabled")
NGINX_METABLOGS_CONF = Path("/etc/nginx/sites-enabled/metablogizer")
BASE_PORT = 8900
DEFAULT_DOMAIN_SUFFIX = ".gk2.secubox.in"
# Internal IP where nginx listens for metablogizer sites
NGINX_BACKEND_IP = "192.168.1.200"

import logging
from site_schema import enrich as _schema_enrich, validate as _schema_validate
from rmtree import force_remove as _rmtree_force
from webhook import (
    classify_payload,
    git_pull,
    git_commit_push,
    list_deploys as _list_deploys,
    load_secret,
    site_lock,
    verify_signature,
    _record_deploy,
)

logger = logging.getLogger("metablogizer")


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


def _load_site_json(site_dir):
    """Read site.json (if any), enrich from git, validate (warn-only).

    Always returns a dict containing at least `name`. Missing/malformed
    files are tolerated — the API stays up.
    """
    name = site_dir.name
    config_file = site_dir / "site.json"
    doc = {}
    if config_file.exists():
        try:
            doc = json.loads(config_file.read_text())
        except json.JSONDecodeError as e:
            logger.warning("site.json malformed for %s: %s", name, e)
            doc = {}
    # Always anchor the name field to the dir name (defensive)
    doc["name"] = name
    doc = _schema_enrich(doc, site_dir)
    ok, errs = _schema_validate(doc)
    if not ok:
        logger.warning("site.json schema violations for %s: %s", name, errs)
    return doc


# In-memory cache for load_sites(). 166 sites × (enrich+validate+du -sh)
# is ~5-10s per call; the dashboard polls 3 endpoints every 60s and the
# single uvicorn worker queues them. Cache for 30s, invalidated by
# _invalidate_sites_cache() in every write path (POST/DELETE/publish).
_SITES_CACHE: Optional[List[dict]] = None
_SITES_CACHE_AT: float = 0.0
_SITES_CACHE_TTL: float = 30.0


def _invalidate_sites_cache() -> None:
    """Drop the cached site list. Call after any site directory change."""
    global _SITES_CACHE, _SITES_CACHE_AT
    _SITES_CACHE = None
    _SITES_CACHE_AT = 0.0


def load_sites() -> List[dict]:
    """Load all sites from directory (cached, 30s TTL)."""
    global _SITES_CACHE, _SITES_CACHE_AT
    import time
    now = time.monotonic()
    if _SITES_CACHE is not None and (now - _SITES_CACHE_AT) < _SITES_CACHE_TTL:
        return _SITES_CACHE

    sites = []
    if not SITES_ROOT.exists():
        _SITES_CACHE = sites
        _SITES_CACHE_AT = now
        return sites

    for site_dir in SITES_ROOT.iterdir():
        if not site_dir.is_dir() or site_dir.name.startswith("."):
            continue

        name = site_dir.name
        domain = f"{name}{DEFAULT_DOMAIN_SUFFIX}"  # Use .gk2.secubox.in instead of .local
        port = BASE_PORT
        published = False

        # Read site config (via the schema-aware helper).
        cfg = _load_site_json(site_dir)
        saved_domain = cfg.get("domain", "") or ""
        if saved_domain.endswith(".local"):
            domain = saved_domain.replace(".local", DEFAULT_DOMAIN_SUFFIX)
        elif saved_domain:
            domain = saved_domain
        port = cfg.get("port", BASE_PORT)

        # Check if published (in unified config)
        if NGINX_METABLOGS_CONF.exists():
            content = NGINX_METABLOGS_CONF.read_text()
            published = f"root {site_dir}" in content or f"root {site_dir}/public" in content

        # Get size
        size = "0"
        success, out, _ = run_cmd(["du", "-sh", str(site_dir)])
        if success:
            size = out.split()[0]

        entry = {
            "name": name,
            "domain": domain,
            "port": port,
            "published": published,
            "directory": str(site_dir),
            "size": size,
        }
        # Overlay schema-enriched fields (version, last_updated, etc.)
        for key in ("version", "title", "description", "category",
                    "streamlit_app", "tags", "last_updated"):
            if key in cfg and cfg[key] is not None:
                entry[key] = cfg[key]
        sites.append(entry)

    sites_sorted = sorted(sites, key=lambda x: x.get("port", BASE_PORT))
    _SITES_CACHE = sites_sorted
    _SITES_CACHE_AT = now
    return sites_sorted


def regenerate_nginx_config() -> tuple:
    """Regenerate the unified nginx config for all metablogizer sites.

    Returns (success, sites_count, message)
    """
    sites = load_sites()
    if not sites:
        return True, 0, "No sites to publish"

    config_lines = ["# Metablogizer nginx config - auto-generated\n"]

    for site in sites:
        name = site["name"]
        domain = site["domain"]
        port = site.get("port", BASE_PORT)
        site_dir = Path(site["directory"])
        size = site.get("size", "0")

        # Use public/ subdirectory if exists, otherwise site root
        public_dir = site_dir / "public"
        root_dir = str(public_dir) if public_dir.exists() else str(site_dir)

        # Check if site is empty (size is 0 or only contains site.json)
        is_empty = size in ("0", "0B", "4.0K") and not (Path(root_dir) / "index.html").exists()

        if is_empty:
            # Empty site - redirect to funky error page
            config_lines.append(f"""
server {{
    listen 0.0.0.0:{port};
    server_name {domain};
    root /usr/share/secubox/www/metablogizer;
    location / {{
        try_files /empty-site.html =404;
    }}
}}
""")
        else:
            # Normal site with content
            config_lines.append(f"""
server {{
    listen 0.0.0.0:{port};
    server_name {domain};
    root {root_dir};
    index index.html;
    location / {{
        try_files $uri $uri/ /index.html;
    }}
}}
""")

    # Write config
    try:
        NGINX_METABLOGS_CONF.parent.mkdir(parents=True, exist_ok=True)
        NGINX_METABLOGS_CONF.write_text("".join(config_lines))

        # Test nginx config (use sudo if needed)
        success, _, err = run_cmd(["sudo", "-n", "nginx", "-t"])
        if not success:
            # Try without sudo (if running as root)
            success, _, err = run_cmd(["nginx", "-t"])
            if not success:
                # Skip test and just reload - let systemd handle it
                logger.warning(f"Nginx test skipped: {err}")

        # Reload nginx (use sudo if needed)
        success, _, _ = run_cmd(["sudo", "-n", "systemctl", "reload", "nginx"])
        if not success:
            run_cmd(["systemctl", "reload", "nginx"])

        logger.info(f"Published {len(sites)} metablogizer sites")
        return True, len(sites), f"Published {len(sites)} sites"
    except Exception as e:
        return False, 0, str(e)


# =============================================================================
# STARTUP - Auto-publish on service start
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Auto-publish all sites when service starts"""
    if AUTO_PUBLISH:
        logger.info("Auto-publishing metablogizer sites on startup...")
        success, count, msg = regenerate_nginx_config()
        if success:
            logger.info(f"Startup auto-publish complete: {msg}")
        else:
            logger.warning(f"Startup auto-publish failed: {msg}")


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


@app.get("/health/{domain}")
async def check_site_health(domain: str):
    """Check health of a specific site by probing HTTP/HTTPS"""
    import httpx

    result = {
        "domain": domain,
        "http": None,
        "https": None,
        "waf": None,
        "error": None
    }

    try:
        # Check HTTPS (primary)
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            try:
                resp = await client.get(f"https://{domain}/", headers={"Host": domain})
                result["https"] = resp.status_code
                result["waf"] = resp.headers.get("X-SecuBox-WAF", "unknown")
            except Exception as e:
                result["https"] = 0
                result["error"] = str(e)

            # Check HTTP (secondary)
            try:
                resp = await client.get(f"http://{domain}/", headers={"Host": domain})
                result["http"] = resp.status_code
            except Exception:
                result["http"] = 0

    except Exception as e:
        result["error"] = str(e)

    return result


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


@app.get("/access/detailed")
def get_access_detailed():
    """Get all published sites with certificate info and sizes"""
    import subprocess
    from datetime import datetime

    sites = load_sites()
    detailed = []

    for s in sites:
        if not s.get("published"):
            continue

        domain = s["domain"]
        name = s["name"]
        site_dir = SITES_ROOT / name

        # Get size
        size = "-"
        if site_dir.exists():
            try:
                result = subprocess.run(
                    ["du", "-sh", str(site_dir)],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    size = result.stdout.split()[0]
            except:
                pass

        # Check certificate
        cert_info = {"exists": False}
        cert_paths = [
            Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem"),
            Path(f"/etc/haproxy/certs/{domain}.pem"),
        ]

        for cert_path in cert_paths:
            if cert_path.exists():
                cert_info["exists"] = True
                try:
                    result = subprocess.run(
                        ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        expiry_str = result.stdout.strip().replace("notAfter=", "")
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        cert_info["expiry"] = expiry.strftime("%Y-%m-%d")
                        cert_info["expired"] = expiry < datetime.now()
                except:
                    pass
                break

        detailed.append({
            "name": name,
            "domain": domain,
            "url": f"https://{domain}",
            "size": size,
            "certificate": cert_info,
        })

    return {"sites": detailed, "count": len(detailed)}


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
    sites = load_sites()
    return {"sites": sites, "count": len(sites)}


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

    _invalidate_sites_cache()
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

    # Sites cloned from Gitea (sub-B of #49) carry a .git subtree whose pack
    # files are 0444 and whose directories may be 0500 — shutil.rmtree then
    # trips on os.open(..., O_RDONLY, dir_fd=topfd). _rmtree_force chmods
    # restricted entries to 0700 and retries.
    _rmtree_force(site_dir)

    _invalidate_sites_cache()
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

    _invalidate_sites_cache()
    return {"success": True, "name": name, "domain": domain, "url": f"http://{domain}"}


@app.post("/site/{name}/unpublish", dependencies=[Depends(require_jwt)])
async def unpublish_site(name: str):
    """Unpublish a site"""
    (NGINX_ENABLED_DIR / f"{name}.conf").unlink(missing_ok=True)
    run_cmd(["systemctl", "reload", "nginx"])

    _invalidate_sites_cache()
    return {"success": True, "name": name}


@app.post("/site/{name}/deploy", dependencies=[Depends(require_jwt)])
async def deploy_site(name: str):
    """Manually pull a site's latest content from its git repo and redeploy.

    Same operation as the Gitea push webhook, but triggered on demand from the
    dashboard's per-site update icon. Serialized against webhook deploys via the
    shared per-site lock.
    """
    import asyncio
    import time

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")
    if not (site_dir / ".git").exists():
        raise HTTPException(400, "Site has no git repo — nothing to update")

    # Pull whatever branch the working tree is on (webhook uses default_branch;
    # for a manual refresh the currently checked-out branch is the right target).
    try:
        branch = subprocess.run(
            ["git", "-c", f"safe.directory={site_dir}", "-C", str(site_dir),
             "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout.strip() or "main"
    except subprocess.CalledProcessError:
        raise HTTPException(500, "cannot determine git branch")

    lock = await site_lock(name)
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()
    try:
        async with lock:
            old_domain = _read_domain(site_dir)
            old, new = await loop.run_in_executor(None, git_pull, site_dir, branch)
            new_domain = _read_domain(site_dir)
            _invalidate_sites_cache()
            domain_changed = old_domain != new_domain
            if domain_changed:
                await loop.run_in_executor(None, regenerate_nginx_config)
        duration_ms = int((time.monotonic() - t0) * 1000)
        _record_deploy({
            "site": name, "from": old, "to": new,
            "duration_ms": duration_ms, "timestamp": time.time(),
            "domain_changed": domain_changed, "source": "manual",
        })
        logger.info(
            f"manual deploy site={name} from={old[:8]} to={new[:8]} "
            f"duration_ms={duration_ms} domain_changed={domain_changed}"
        )
        return {"success": True, "deployed": name, "from": old, "to": new,
                "updated": old != new, "duration_ms": duration_ms,
                "domain_changed": domain_changed}
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "git-timeout")
    except subprocess.CalledProcessError as e:
        logger.error(f"manual deploy git failed site={name}: {e.stderr}")
        raise HTTPException(500, "git-failed")


@app.post("/republish-all", dependencies=[Depends(require_jwt)])
async def republish_all():
    """Republish all sites by regenerating nginx config"""
    success, count, message = regenerate_nginx_config()
    _invalidate_sites_cache()
    return {
        "success": success,
        "sites_published": count,
        "message": message
    }


# =============================================================================
# DEPLOY WEBHOOK (Gitea push → site update)
# =============================================================================

@app.post("/webhook")
async def webhook(request: Request):
    """Gitea push webhook. HMAC-verified; deploys metablog-* default-branch pushes."""
    import asyncio
    import time
    from fastapi import HTTPException

    body = await request.body()
    sig = request.headers.get("X-Gitea-Signature", "")

    try:
        secret = load_secret()
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"webhook secret unavailable: {e}")
        raise HTTPException(503, "webhook secret not configured")

    if not verify_signature(secret, body, sig):
        raise HTTPException(401)

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "invalid-json")

    decision, info = classify_payload(payload)
    if decision == "malformed":
        raise HTTPException(400, info.get("reason", "malformed"))
    if decision == "skip":
        logger.info(f"webhook skip {info}")
        return {"skip": info["reason"], **{k: v for k, v in info.items() if k != "reason"}}

    site_name = info["site"]
    branch = info["branch"]
    site_dir = SITES_ROOT / site_name

    if not site_dir.exists():
        logger.info(f"webhook unknown-site {site_name}")
        return {"skip": "unknown-site", "site": site_name}
    if not (site_dir / ".git").exists():
        logger.info(f"webhook no-git-dir {site_name}")
        return {"skip": "no-git-dir", "site": site_name}

    lock = await site_lock(site_name)
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()

    try:
        async with lock:
            old_domain = _read_domain(site_dir)
            old, new = await loop.run_in_executor(None, git_pull, site_dir, branch)
            new_domain = _read_domain(site_dir)

            _invalidate_sites_cache()

            domain_changed = old_domain != new_domain
            if domain_changed:
                await loop.run_in_executor(None, regenerate_nginx_config)

        duration_ms = int((time.monotonic() - t0) * 1000)
        entry = {
            "site": site_name,
            "from": old,
            "to": new,
            "duration_ms": duration_ms,
            "timestamp": time.time(),
            "domain_changed": domain_changed,
            "source": "webhook",
        }
        _record_deploy(entry)
        logger.info(
            f"deploy site={site_name} from={old[:8]} to={new[:8]} "
            f"duration_ms={duration_ms} domain_changed={domain_changed}"
        )
        return {"deployed": site_name, "from": old, "to": new,
                "duration_ms": duration_ms, "domain_changed": domain_changed}

    except subprocess.TimeoutExpired as e:
        logger.error(f"webhook git timeout site={site_name}: {e}")
        raise HTTPException(504, "git-timeout")
    except subprocess.CalledProcessError as e:
        logger.error(f"webhook git failed site={site_name}: {e.stderr}")
        raise HTTPException(500, "git-failed")


@app.get("/deploys", dependencies=[Depends(require_jwt)])
async def deploys():
    """Last 50 deploy records (newest first)."""
    return _list_deploys()


def _read_domain(site_dir: Path) -> str:
    """Best-effort read of site.json:domain. Returns '' on any error."""
    try:
        return (_load_site_json(site_dir) or {}).get("domain", "") or ""
    except Exception:
        return ""


@app.post("/site/{name}/upload", dependencies=[Depends(require_jwt)])
async def upload_content(name: str, file: UploadFile = File(...)):
    """Upload content to a site (.zip / .tar.gz archive, or a single .html).

    Content is written to the directory nginx actually serves for the site.
    The served-root convention (matching regenerate_nginx_config / publish) is
    `<site>/public` when that dir already exists, else the site dir root — so we
    must NOT create public/ here, or we'd silently move the served root out from
    under an already-published site and the upload wouldn't show up.
    """
    import asyncio

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        site_dir.mkdir(parents=True)

    public_dir = site_dir / "public"
    target_dir = public_dir if public_dir.exists() else site_dir

    fname = (file.filename or "").lower()

    # A bare HTML page becomes the site's index — no temp file / extraction.
    if fname.endswith((".html", ".htm")):
        content = await file.read()
        (target_dir / "index.html").write_bytes(content)
        _invalidate_sites_cache()
        version = await _version_upload(name, site_dir, file.filename or "index.html")
        return {"success": True, "name": name, "kind": "html", "target": str(target_dir), "gitea": version}

    content = await file.read()
    temp_file = site_dir / f"_upload_{file.filename}"
    temp_file.write_bytes(content)

    try:
        if fname.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(temp_file, 'r') as zf:
                zf.extractall(target_dir)
        elif fname.endswith((".tar.gz", ".tgz")):
            import tarfile
            with tarfile.open(temp_file, 'r:gz') as tf:
                tf.extractall(target_dir)
        else:
            temp_file.unlink(missing_ok=True)
            raise HTTPException(400, "Unsupported format. Use .zip, .tar.gz or .html")

        temp_file.unlink()
    except HTTPException:
        raise
    except Exception as e:
        temp_file.unlink(missing_ok=True)
        raise HTTPException(400, f"Failed to extract: {e}")

    _invalidate_sites_cache()
    version = await _version_upload(name, site_dir, file.filename or "archive")
    return {"success": True, "name": name, "kind": "archive", "target": str(target_dir), "gitea": version}


async def _version_upload(name: str, site_dir: Path, filename: str) -> dict:
    """Commit + push this upload into the site's Gitea repo as a new version.

    Runs under the shared per-site lock so it serializes against webhook/manual
    deploy pulls, and off the event loop (git blocks). Best-effort: a Gitea
    failure is reported in the response but never fails the upload itself.
    """
    import time
    lock = await site_lock(name)
    loop = asyncio.get_running_loop()
    # A monotonic stamp keeps commit messages unique/ordered without needing
    # wall-clock parsing; the operator sees "upload: <file>" + a counter.
    message = f"upload: {filename}"
    try:
        async with lock:
            return await loop.run_in_executor(None, git_commit_push, site_dir, message)
    except Exception as e:  # never let versioning break the upload response
        logger.warning(f"gitea version wrapper failed site={name}: {e}")
        return {"pushed": False, "committed": False, "commit": None, "reason": "error"}


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


@app.get("/site/{name}/export", dependencies=[Depends(require_jwt)])
async def export_site(name: str):
    """Export complete site package as ZIP archive

    Includes:
    - Site content (public/)
    - site.json config
    - nginx.conf (generated)
    - haproxy.cfg (snippet for HAProxy vhost)
    - certificate.pem (if available)
    - README.md (republishing instructions)
    """
    from fastapi.responses import FileResponse
    import zipfile
    import tempfile
    from datetime import datetime

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Read site config
    domain = f"{name}.gk2.secubox.in"
    config_file = site_dir / "site.json"
    site_config = {"name": name, "domain": domain}
    if config_file.exists():
        try:
            site_config = json.loads(config_file.read_text())
            domain = site_config.get("domain", domain)
        except:
            pass

    # Create temporary ZIP file
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        with zipfile.ZipFile(tmp.name, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 1. Site content
            for file_path in site_dir.rglob("*"):
                if file_path.is_file():
                    arcname = f"content/{file_path.relative_to(site_dir)}"
                    zf.write(file_path, arcname)

            # 2. Site config
            zf.writestr("config/site.json", json.dumps(site_config, indent=2))

            # 3. Nginx config
            public_dir = site_dir / "public"
            root_dir = str(public_dir) if public_dir.exists() else str(site_dir)
            nginx_conf = f"""# Nginx config for {name}
# Generated by SecuBox MetaBlogizer
# Import: cp nginx.conf /etc/nginx/sites-available/{name}.conf

server {{
    listen 80;
    listen 443 ssl http2;
    server_name {domain};

    # SSL (adjust paths if using custom certs)
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    root {root_dir};
    index index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.html =404;
    }}

    # Cache static assets
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {{
        expires 1y;
        add_header Cache-Control "public, immutable";
    }}

    access_log /var/log/nginx/{name}_access.log;
    error_log /var/log/nginx/{name}_error.log;
}}
"""
            zf.writestr("config/nginx.conf", nginx_conf)

            # 4. HAProxy config snippet
            haproxy_conf = f"""# HAProxy vhost snippet for {name}
# Add ACL and use_backend rules to your haproxy.cfg frontend

# ACL (add to frontend section)
acl host_{name.replace('.', '_').replace('-', '_')} hdr(host) -i {domain}

# Backend routing (add after ACLs)
use_backend mitmproxy_inspector if host_{name.replace('.', '_').replace('-', '_')}

# Note: Requires mitmproxy route configuration
# Add to /srv/mitmproxy/haproxy-routes.json:
# "{domain}": ["10.100.0.1", 8900]
"""
            zf.writestr("config/haproxy.cfg", haproxy_conf)

            # 5. Certificate (if available)
            cert_paths = [
                Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem"),
                Path(f"/etc/haproxy/certs/{domain}.pem"),
            ]
            cert_found = False
            for cert_path in cert_paths:
                if cert_path.exists():
                    try:
                        zf.write(cert_path, "certs/certificate.pem")
                        # Also try to get private key
                        key_path = cert_path.parent / "privkey.pem"
                        if key_path.exists():
                            zf.write(key_path, "certs/privkey.pem")
                        cert_found = True
                    except:
                        pass
                    break

            # 6. README with republishing instructions
            readme = f"""# {name} - Site Export Package

**Domain:** {domain}
**Exported:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Generator:** SecuBox MetaBlogizer

## Contents

```
{name}-export.zip/
├── content/           # Site files (HTML, CSS, JS, images)
│   ├── public/        # Public web root
│   └── site.json      # Site configuration
├── config/
│   ├── site.json      # Site configuration
│   ├── nginx.conf     # Nginx vhost config
│   └── haproxy.cfg    # HAProxy routing snippet
├── certs/             # SSL certificates (if available)
│   ├── certificate.pem
│   └── privkey.pem
└── README.md          # This file
```

## Quick Republish (SecuBox)

1. Upload ZIP to target SecuBox:
   ```bash
   scp {name}-export.zip root@secubox:/tmp/
   ```

2. Extract and deploy:
   ```bash
   cd /srv/metablogizer/sites
   unzip /tmp/{name}-export.zip -d {name}/
   mv {name}/content/* {name}/
   rm -rf {name}/content
   systemctl restart secubox-metablogizer
   ```

## Manual Republish (Any Server)

### Nginx

1. Copy content:
   ```bash
   mkdir -p /var/www/{name}
   cp -r content/public/* /var/www/{name}/
   ```

2. Install nginx config:
   ```bash
   cp config/nginx.conf /etc/nginx/sites-available/{name}.conf
   ln -s /etc/nginx/sites-available/{name}.conf /etc/nginx/sites-enabled/
   nginx -t && systemctl reload nginx
   ```

3. SSL certificate (if included):
   ```bash
   mkdir -p /etc/ssl/{name}
   cp certs/*.pem /etc/ssl/{name}/
   ```
   Update nginx.conf paths accordingly.

### HAProxy (with SecuBox WAF)

1. Add ACL to haproxy.cfg:
   ```
   acl host_{name.replace('.', '_').replace('-', '_')} hdr(host) -i {domain}
   use_backend mitmproxy_inspector if host_{name.replace('.', '_').replace('-', '_')}
   ```

2. Add mitmproxy route:
   ```json
   "{domain}": ["10.100.0.1", 8900]
   ```

3. Reload:
   ```bash
   haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy
   systemctl restart mitmproxy
   ```

## DNS Configuration

Point `{domain}` to your server IP:
```
{domain}. IN A <your-server-ip>
```

Or use wildcard if using subdomain:
```
*.gk2.secubox.in. IN A <your-server-ip>
```

## Certificate Status

{'✅ Certificate included in export' if cert_found else '⚠️ No certificate found - use certbot to generate:'}
{'' if cert_found else f'certbot certonly --webroot -w /var/www/{name} -d {domain}'}

---
Generated by SecuBox MetaBlogizer
https://secubox.in | CyberMind
"""
            zf.writestr("README.md", readme)

        return FileResponse(
            tmp.name,
            media_type="application/zip",
            filename=f"{name}-export.zip",
            headers={"Content-Disposition": f'attachment; filename="{name}-export.zip"'}
        )


@app.get("/site/{name}/cert", dependencies=[Depends(require_jwt)])
async def get_site_cert(name: str):
    """Get SSL certificate for site"""
    from fastapi.responses import FileResponse

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Read site config to get domain
    domain = f"{name}.gk2.secubox.in"
    config_file = site_dir / "site.json"
    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            domain = cfg.get("domain", domain)
        except:
            pass

    # Check certbot cert locations
    cert_paths = [
        Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem"),
        Path(f"/etc/letsencrypt/live/{domain}/cert.pem"),
        Path(f"/etc/haproxy/certs/{domain}.pem"),
        Path(f"/etc/ssl/certs/{domain}.pem"),
    ]

    for cert_path in cert_paths:
        if cert_path.exists():
            return FileResponse(
                str(cert_path),
                media_type="application/x-pem-file",
                filename=f"{domain}.pem",
                headers={"Content-Disposition": f'attachment; filename="{domain}.pem"'}
            )

    raise HTTPException(404, f"No certificate found for {domain}")


@app.get("/site/{name}/certificate", dependencies=[Depends(require_jwt)])
def get_certificate_info(name: str):
    """Get certificate information for a site"""
    import subprocess
    from datetime import datetime

    site_dir = SITES_ROOT / name
    if not site_dir.exists():
        raise HTTPException(404, "Site not found")

    # Read site config to get domain
    domain = f"{name}.gk2.secubox.in"
    config_file = site_dir / "site.json"
    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            domain = cfg.get("domain", domain)
        except:
            pass

    # Check certbot cert
    cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    if not cert_path.exists():
        cert_path = Path(f"/etc/haproxy/certs/{domain}.pem")

    if not cert_path.exists():
        return {"exists": False, "domain": domain}

    # Get cert expiry
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Parse expiry: notAfter=May 10 12:00:00 2026 GMT
            expiry_str = result.stdout.strip().replace("notAfter=", "")
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            expired = expiry < datetime.now()
            return {
                "exists": True,
                "domain": domain,
                "expiry": expiry.strftime("%Y-%m-%d"),
                "expired": expired,
                "path": str(cert_path)
            }
    except Exception as e:
        return {"exists": True, "domain": domain, "error": str(e)}

    return {"exists": True, "domain": domain, "path": str(cert_path)}
