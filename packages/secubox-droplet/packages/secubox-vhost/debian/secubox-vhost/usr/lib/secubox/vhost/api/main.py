"""secubox-vhost — Virtual Host Manager API"""
import os
import subprocess
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-vhost", version="1.0.0", root_path="/api/v1/vhost")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("vhost")

NGINX_CONF_DIR = "/etc/nginx/sites-available"
NGINX_ENABLED_DIR = "/etc/nginx/sites-enabled"
ACME_DIR = "/etc/acme"


def _cfg():
    cfg = get_config("vhost")
    return {
        "nginx_conf_dir": cfg.get("nginx_conf_dir", NGINX_CONF_DIR) if cfg else NGINX_CONF_DIR,
        "acme_dir": cfg.get("acme_dir", ACME_DIR) if cfg else ACME_DIR,
    }


def _load_vhosts() -> List[dict]:
    """Load vhosts from nginx config files."""
    vhosts = []
    conf_dir = Path(_cfg()["nginx_conf_dir"])
    if not conf_dir.exists():
        return vhosts

    for conf_file in conf_dir.glob("*.conf"):
        if conf_file.name.startswith("_") or conf_file.name == "default":
            continue
        domain = conf_file.stem
        enabled = Path(NGINX_ENABLED_DIR) / conf_file.name
        content = conf_file.read_text()
        ssl = "ssl_certificate" in content
        backend = ""
        if "proxy_pass" in content:
            for line in content.split("\n"):
                if "proxy_pass" in line:
                    backend = line.split("proxy_pass")[1].strip().rstrip(";")
                    break
        vhosts.append({
            "domain": domain, "enabled": enabled.exists(), "ssl": ssl, "backend": backend,
        })
    return vhosts


def _get_cert_info(domain: str) -> dict:
    acme_dir = Path(_cfg()["acme_dir"])
    cert_path = acme_dir / domain / "fullchain.cer"
    if not cert_path.exists():
        return {"exists": False}
    info = {"exists": True, "cert_path": str(cert_path)}
    try:
        r = subprocess.run(["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"],
                          capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            info["expires"] = r.stdout.strip().split("=")[1]
    except Exception:
        pass
    return info


@router.get("/status")
async def status():
    """VHost Manager status (public)."""
    vhosts = _load_vhosts()
    nginx_running = subprocess.run(["pgrep", "nginx"], capture_output=True).returncode == 0
    return {
        "nginx_running": nginx_running,
        "vhost_count": len(vhosts),
        "enabled_count": sum(1 for v in vhosts if v.get("enabled")),
        "ssl_count": sum(1 for v in vhosts if v.get("ssl")),
    }


@router.get("/vhosts")
async def list_vhosts():
    """List all vhosts (public)."""
    return {"vhosts": _load_vhosts()}


@router.get("/vhost/{domain}")
async def get_vhost(domain: str, user=Depends(require_jwt)):
    vhosts = _load_vhosts()
    for v in vhosts:
        if v["domain"] == domain:
            v["certificate"] = _get_cert_info(domain)
            return v
    raise HTTPException(404, f"VHost not found: {domain}")


class VHostCreate(BaseModel):
    domain: str
    backend: str
    ssl: bool = False
    ssl_redirect: bool = True
    enabled: bool = True


def _gen_nginx_conf(domain: str, backend: str, ssl: bool, ssl_redirect: bool) -> str:
    acme_dir = _cfg()["acme_dir"]
    conf = f"server {{\n    listen 80;\n    server_name {domain};\n"
    if ssl and ssl_redirect:
        conf += f"""
    location /.well-known/acme-challenge/ {{ root /var/www/acme; }}
    location / {{ return 301 https://$host$request_uri; }}
}}
server {{
    listen 443 ssl http2;
    server_name {domain};
    ssl_certificate {acme_dir}/{domain}/fullchain.cer;
    ssl_certificate_key {acme_dir}/{domain}/{domain}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
"""
    conf += f"""
    location / {{
        proxy_pass {backend};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
    return conf


@router.post("/vhost")
async def add_vhost(req: VHostCreate, user=Depends(require_jwt)):
    conf_dir = Path(_cfg()["nginx_conf_dir"])
    conf_file = conf_dir / f"{req.domain}.conf"
    if conf_file.exists():
        raise HTTPException(400, f"VHost exists: {req.domain}")
    conf_dir.mkdir(parents=True, exist_ok=True)
    conf_file.write_text(_gen_nginx_conf(req.domain, req.backend, req.ssl, req.ssl_redirect))
    if req.enabled:
        (Path(NGINX_ENABLED_DIR) / f"{req.domain}.conf").symlink_to(conf_file)
    subprocess.run(["systemctl", "reload", "nginx"], timeout=10)
    log.info("Created vhost: %s", req.domain)
    return {"success": True, "domain": req.domain}


@router.delete("/vhost/{domain}")
async def delete_vhost(domain: str, user=Depends(require_jwt)):
    conf_file = Path(_cfg()["nginx_conf_dir"]) / f"{domain}.conf"
    if not conf_file.exists():
        raise HTTPException(404, f"VHost not found: {domain}")
    (Path(NGINX_ENABLED_DIR) / f"{domain}.conf").unlink(missing_ok=True)
    conf_file.unlink()
    subprocess.run(["systemctl", "reload", "nginx"], timeout=10)
    log.info("Deleted vhost: %s", domain)
    return {"success": True, "domain": domain}


@router.get("/certificates")
async def list_certificates():
    """List certificates (public)."""
    acme_dir = Path(_cfg()["acme_dir"])
    certs = []
    if acme_dir.exists():
        for d in acme_dir.iterdir():
            if d.is_dir():
                info = _get_cert_info(d.name)
                if info.get("exists"):
                    certs.append({"domain": d.name, "expires": info.get("expires", "")})
    return {"certificates": certs}


class CertRequest(BaseModel):
    domain: str
    email: Optional[str] = None


@router.post("/certificate/issue")
async def issue_certificate(req: CertRequest, user=Depends(require_jwt)):
    email = req.email or f"admin@{req.domain}"
    r = subprocess.run(
        ["acme.sh", "--issue", "-d", req.domain, "--webroot", "/var/www/acme", "--accountemail", email],
        capture_output=True, text=True, timeout=120
    )
    log.info("Cert issue for %s: %s", req.domain, "ok" if r.returncode == 0 else "fail")
    return {"success": r.returncode == 0, "domain": req.domain, "output": (r.stdout or r.stderr)[:500]}


@router.post("/reload")
async def reload_nginx(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True, timeout=10)
    return {"success": r.returncode == 0}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "vhost"}


app.include_router(router)
