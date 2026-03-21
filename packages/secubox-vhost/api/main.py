"""secubox-vhost — Virtual Host Manager (nginx + certbot)"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger
import subprocess, json
from pathlib import Path
from jinja2 import Environment, BaseLoader

app = FastAPI(title="secubox-vhost", version="1.0.0", root_path="/api/v1/vhost")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("vhost")

SITES_DIR = Path("/etc/nginx/sites-available")
ENABLED_DIR = Path("/etc/nginx/sites-enabled")

VHOST_TPL = """server {
    listen 443 ssl http2;
    server_name {{ domain }};
    ssl_certificate     /etc/secubox/tls/{{ domain }}.crt;
    ssl_certificate_key /etc/secubox/tls/{{ domain }}.key;
    location / {
        proxy_pass http://{{ upstream }};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
server { listen 80; server_name {{ domain }}; return 301 https://$host$request_uri; }
"""

def _list_sites() -> list[dict]:
    if not SITES_DIR.exists(): return []
    result = []
    for f in SITES_DIR.glob("*.conf"):
        enabled = (ENABLED_DIR / f.name).exists()
        result.append({"name": f.stem, "file": str(f), "enabled": enabled,
                       "size": f.stat().st_size})
    return result

@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Statut du service nginx et des vhosts."""
    r = subprocess.run(["systemctl", "is-active", "nginx"], capture_output=True, text=True)
    sites = _list_sites()
    return {
        "nginx_running": r.stdout.strip() == "active",
        "vhosts_count": len(sites),
        "enabled_count": sum(1 for s in sites if s["enabled"]),
    }


@router.get("/list_vhosts")
async def list_vhosts(user=Depends(require_jwt)):
    return _list_sites()


@router.get("/get_vhost")
async def get_vhost(domain: str, user=Depends(require_jwt)):
    """Lire la config d'un vhost."""
    conf_file = SITES_DIR / f"{domain}.conf"
    if not conf_file.exists():
        raise HTTPException(404, f"Vhost {domain} not found")
    return {
        "domain": domain,
        "config": conf_file.read_text(),
        "enabled": (ENABLED_DIR / f"{domain}.conf").exists(),
    }


class UpdateVhostRequest(BaseModel):
    domain: str
    config: str


@router.post("/update_vhost")
async def update_vhost(req: UpdateVhostRequest, user=Depends(require_jwt)):
    """Mettre à jour la config d'un vhost."""
    conf_file = SITES_DIR / f"{req.domain}.conf"
    conf_file.write_text(req.config)
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if r.returncode != 0:
        raise HTTPException(400, f"nginx -t failed: {r.stderr[:300]}")
    subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
    return {"success": True, "domain": req.domain}


@router.get("/test_backend")
async def test_backend(upstream: str, user=Depends(require_jwt)):
    """Tester la connectivité vers un backend."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"http://{upstream}/")
            return {"reachable": True, "status_code": r.status_code}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


@router.post("/request_cert")
async def request_cert(domain: str, user=Depends(require_jwt)):
    """Demander un certificat Let's Encrypt."""
    r = subprocess.run(
        ["certbot", "certonly", "--nginx", "-d", domain, "--non-interactive", "--agree-tos"],
        capture_output=True, text=True, timeout=120
    )
    log.info("request_cert %s: %s", domain, r.returncode)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:500]}


@router.post("/reload_nginx")
async def reload_nginx(user=Depends(require_jwt)):
    """Recharger nginx."""
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if r.returncode != 0:
        return {"success": False, "error": r.stderr[:300]}
    r2 = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    return {"success": r2.returncode == 0}


@router.get("/get_access_logs")
async def get_access_logs(domain: str = "", lines: int = 100, user=Depends(require_jwt)):
    """Lire les logs d'accès."""
    log_file = f"/var/log/nginx/{domain}.access.log" if domain else "/var/log/nginx/access.log"
    r = subprocess.run(["tail", "-n", str(lines), log_file], capture_output=True, text=True)
    return {"lines": r.stdout.splitlines()}

@router.get("/ssl_status")
async def ssl_status(user=Depends(require_jwt)):
    r = subprocess.run(["certbot", "certificates", "--non-interactive"],
                       capture_output=True, text=True, timeout=15)
    return {"output": r.stdout, "certbot_ok": r.returncode == 0}

@router.get("/get_certificates")
async def get_certificates(user=Depends(require_jwt)):
    certs_dir = Path("/etc/letsencrypt/live")
    if not certs_dir.exists(): return []
    return [{"domain": d.name} for d in certs_dir.iterdir() if d.is_dir()]

@router.get("/get_logs")
async def get_logs(lines: int = 50, user=Depends(require_jwt)):
    r = subprocess.run(["tail", "-n", str(lines), "/var/log/nginx/error.log"],
                       capture_output=True, text=True)
    return {"lines": r.stdout.splitlines()}

class VhostRequest(BaseModel):
    domain:   str
    upstream: str
    ssl_mode: str = "selfsigned"

@router.post("/add_vhost")
async def add_vhost(req: VhostRequest, user=Depends(require_jwt)):
    env = Environment(loader=BaseLoader())
    tpl = env.from_string(VHOST_TPL)
    conf = tpl.render(domain=req.domain, upstream=req.upstream)
    out = SITES_DIR / f"{req.domain}.conf"
    SITES_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(conf)
    (ENABLED_DIR / f"{req.domain}.conf").symlink_to(out)
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if r.returncode == 0:
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
        return {"success": True, "domain": req.domain}
    out.unlink()
    raise HTTPException(500, f"nginx -t failed: {r.stderr[:300]}")

@router.post("/remove_vhost")
async def remove_vhost(domain: str, user=Depends(require_jwt)):
    for p in [ENABLED_DIR/f"{domain}.conf", SITES_DIR/f"{domain}.conf"]:
        p.unlink(missing_ok=True)
    subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
    return {"success": True, "domain": domain}

@router.get("/health")
async def health(): return {"status": "ok", "module": "vhost"}
app.include_router(router)
