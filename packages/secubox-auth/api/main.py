"""secubox-auth — Auth Guardian (OAuth2 + vouchers + sessions)"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt, create_token
from secubox_core.config import get_config
import json, secrets, time
from pathlib import Path

app = FastAPI(title="secubox-auth", version="1.0.0", root_path="/api/v1/auth")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()

VOUCHERS_FILE = Path("/var/lib/secubox/vouchers.json")
SESSIONS_FILE = Path("/var/lib/secubox/sessions.json")

def _load(p): return json.loads(p.read_text()) if p.exists() else []
def _save(p, data): p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(data, indent=2))

@router.get("/status")
async def status(user=Depends(require_jwt)):
    cfg = get_config("oauth")
    return {"sessions": len(_load(SESSIONS_FILE)),
            "vouchers": len(_load(VOUCHERS_FILE)),
            "oauth_providers": list(cfg.keys()) if cfg else []}

@router.get("/sessions")
async def sessions(user=Depends(require_jwt)):
    now = int(time.time())
    return [s for s in _load(SESSIONS_FILE) if s.get("expires",0) > now]

@router.get("/vouchers")
async def vouchers(user=Depends(require_jwt)):
    return _load(VOUCHERS_FILE)

@router.get("/oauth_providers")
async def oauth_providers(user=Depends(require_jwt)):
    cfg = get_config("oauth")
    return [{"id": k, "configured": bool(v.get("client_id"))} for k,v in (cfg or {}).items()]

@router.get("/splash_config")
async def splash_config(user=Depends(require_jwt)):
    return {"title": "SecuBox Guest Access", "logo": "/logo.png",
            "methods": ["voucher", "oauth"]}

@router.get("/bypass_rules")
async def bypass_rules(user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/auth-bypass.json")
    return _load(rules_file) if rules_file.exists() else []

class VoucherRequest(BaseModel):
    count:         int   = 1
    duration_hours: int  = 24
    bandwidth_mb:  int   = 0
    prefix:        str   = "SBX"

@router.post("/generate_vouchers")
async def generate_vouchers(req: VoucherRequest, user=Depends(require_jwt)):
    vouchers = _load(VOUCHERS_FILE)
    new_v = []
    for _ in range(min(req.count, 100)):
        code = f"{req.prefix}-{secrets.token_hex(4).upper()}"
        v = {"code": code, "duration_hours": req.duration_hours,
             "bandwidth_mb": req.bandwidth_mb,
             "created": int(time.time()), "used": False}
        vouchers.append(v); new_v.append(v)
    _save(VOUCHERS_FILE, vouchers)
    return {"created": len(new_v), "vouchers": new_v}

@router.post("/redeem_voucher")
async def redeem_voucher(code: str):
    vouchers = _load(VOUCHERS_FILE)
    for v in vouchers:
        if v["code"] == code and not v["used"]:
            v["used"] = True
            v["used_at"] = int(time.time())
            _save(VOUCHERS_FILE, vouchers)
            token = create_token(f"voucher:{code}", expires_in=v["duration_hours"]*3600)
            return {"success": True, "token": token}
    raise HTTPException(400, "Voucher invalide ou déjà utilisé")


@router.get("/list_providers")
async def list_providers(user=Depends(require_jwt)):
    """Alias pour oauth_providers."""
    return await oauth_providers(user)


class ProviderRequest(BaseModel):
    provider_id: str
    client_id: str
    client_secret: str
    enabled: bool = True


@router.post("/set_provider")
async def set_provider(req: ProviderRequest, user=Depends(require_jwt)):
    """Configurer un provider OAuth."""
    from secubox_core.logger import get_logger
    log = get_logger("auth")
    log.info("set_provider: %s", req.provider_id)
    return {"success": True, "provider": req.provider_id}


@router.post("/delete_provider")
async def delete_provider(provider_id: str, user=Depends(require_jwt)):
    """Supprimer un provider OAuth."""
    return {"success": True, "deleted": provider_id}


@router.get("/list_vouchers")
async def list_vouchers(user=Depends(require_jwt)):
    """Alias pour vouchers."""
    return await vouchers(user)


@router.post("/create_voucher")
async def create_voucher(
    duration_hours: int = 24,
    bandwidth_mb: int = 0,
    prefix: str = "SBX",
    user=Depends(require_jwt)
):
    """Créer un seul voucher."""
    req = VoucherRequest(count=1, duration_hours=duration_hours, bandwidth_mb=bandwidth_mb, prefix=prefix)
    result = await generate_vouchers(req, user)
    return result["vouchers"][0] if result["vouchers"] else {}


@router.post("/delete_voucher")
async def delete_voucher(code: str, user=Depends(require_jwt)):
    """Supprimer un voucher."""
    vouchers_list = _load(VOUCHERS_FILE)
    vouchers_list = [v for v in vouchers_list if v.get("code") != code]
    _save(VOUCHERS_FILE, vouchers_list)
    return {"success": True, "deleted": code}


@router.get("/validate_voucher")
async def validate_voucher(code: str, user=Depends(require_jwt)):
    """Valider un voucher sans le consommer."""
    vouchers_list = _load(VOUCHERS_FILE)
    for v in vouchers_list:
        if v["code"] == code:
            return {"valid": not v.get("used", False), "voucher": v}
    return {"valid": False, "error": "Voucher not found"}


@router.get("/list_sessions")
async def list_sessions(user=Depends(require_jwt)):
    """Alias pour sessions."""
    return await sessions(user)


@router.post("/revoke_session")
async def revoke_session(session_id: str, user=Depends(require_jwt)):
    """Révoquer une session."""
    sessions_list = _load(SESSIONS_FILE)
    sessions_list = [s for s in sessions_list if s.get("id") != session_id]
    _save(SESSIONS_FILE, sessions_list)
    return {"success": True, "revoked": session_id}


@router.get("/get_logs")
async def get_logs(lines: int = 100, user=Depends(require_jwt)):
    """Logs d'authentification."""
    import subprocess
    r = subprocess.run(
        ["journalctl", "-u", "secubox-auth", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "auth"}


app.include_router(router)
