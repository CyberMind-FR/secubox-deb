"""SecuBox Auth API - OAuth2 + Vouchers + Sessions with Enhanced Monitoring"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt, create_token
from secubox_core.config import get_config
import json
import secrets
import time
import threading
import asyncio
import hashlib
import hmac
import httpx
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

app = FastAPI(title="secubox-auth", version="2.0.0", root_path="/api/v1/auth")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()

# Configuration
DATA_DIR = Path("/var/lib/secubox/auth")
DATA_DIR.mkdir(parents=True, exist_ok=True)
VOUCHERS_FILE = DATA_DIR / "vouchers.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats.json"


class StatsCache:
    """Thread-safe stats cache with TTL."""

    def __init__(self, ttl_seconds: int = 30):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=30)


# Pydantic Models
class VoucherRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=100)
    duration_hours: int = Field(default=24, ge=1, le=8760)
    bandwidth_mb: int = Field(default=0, ge=0)
    prefix: str = Field(default="SBX", max_length=10)


class ProviderRequest(BaseModel):
    provider_id: str
    client_id: str
    client_secret: str
    enabled: bool = True


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["login", "logout", "voucher_redeemed", "session_revoked"])
    secret: Optional[str] = None
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# State
_cleanup_task: Optional[asyncio.Task] = None


def _load(p: Path, default=None):
    """Load JSON file safely."""
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return default if default is not None else []


def _save(p: Path, data):
    """Save JSON file safely."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))


def _load_history() -> List[Dict[str, Any]]:
    return _load(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-2000:]
    _save(HISTORY_FILE, history)


def _load_webhooks() -> List[Dict[str, Any]]:
    return _load(WEBHOOKS_FILE, [])


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    _save(WEBHOOKS_FILE, webhooks)


def _record_event(event: str, details: Optional[Dict] = None):
    """Record an event in history."""
    history = _load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "details": details or {}
    }
    history.append(entry)
    _save_history(history)


async def _send_webhook(url: str, payload: Dict[str, Any], secret: Optional[str] = None):
    """Send webhook notification."""
    try:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload)

        if secret:
            signature = hmac.new(
                secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={signature}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, content=body, headers=headers)
    except Exception:
        pass


async def _notify_webhooks(event: str, data: Dict[str, Any]):
    """Send notifications to all webhooks for event."""
    webhooks = _load_webhooks()
    for webhook in webhooks:
        if webhook.get("enabled", True) and event in webhook.get("events", []):
            await _send_webhook(
                webhook["url"],
                {"event": event, "data": data, "timestamp": datetime.now().isoformat()},
                webhook.get("secret")
            )


def _cleanup_expired():
    """Remove expired sessions and update stats."""
    now = int(time.time())
    sessions = _load(SESSIONS_FILE, [])
    active = [s for s in sessions if s.get("expires", 0) > now]
    expired_count = len(sessions) - len(active)

    if expired_count > 0:
        _save(SESSIONS_FILE, active)
        _record_event("sessions_expired", {"count": expired_count})

    return expired_count


async def _periodic_cleanup():
    """Background task to clean up expired sessions."""
    while True:
        try:
            _cleanup_expired()
        except Exception:
            pass
        await asyncio.sleep(300)  # Every 5 minutes


@app.on_event("startup")
async def startup():
    """Start background cleanup."""
    global _cleanup_task
    _cleanup_task = asyncio.create_task(_periodic_cleanup())


@app.on_event("shutdown")
async def shutdown():
    """Stop background cleanup."""
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()


# Public endpoints
@router.get("/health")
async def health():
    return {"status": "ok", "module": "auth", "version": "2.0.0"}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get auth module status."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    cfg = get_config("oauth")
    now = int(time.time())
    sessions = _load(SESSIONS_FILE, [])
    active_sessions = [s for s in sessions if s.get("expires", 0) > now]
    vouchers = _load(VOUCHERS_FILE, [])

    result = {
        "sessions": {
            "active": len(active_sessions),
            "total": len(sessions)
        },
        "vouchers": {
            "total": len(vouchers),
            "unused": sum(1 for v in vouchers if not v.get("used")),
            "used": sum(1 for v in vouchers if v.get("used"))
        },
        "oauth_providers": list(cfg.keys()) if cfg else [],
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("status", result)
    return result


@router.get("/sessions")
async def sessions(user=Depends(require_jwt)):
    """Get active sessions."""
    now = int(time.time())
    all_sessions = _load(SESSIONS_FILE, [])
    active = []

    for s in all_sessions:
        if s.get("expires", 0) > now:
            session = s.copy()
            session["remaining_seconds"] = s.get("expires", 0) - now
            session["remaining_human"] = str(timedelta(seconds=session["remaining_seconds"]))
            active.append(session)

    return {
        "sessions": active,
        "count": len(active)
    }


@router.get("/sessions/stats")
async def session_stats(user=Depends(require_jwt)):
    """Get session statistics."""
    now = int(time.time())
    sessions = _load(SESSIONS_FILE, [])
    active = [s for s in sessions if s.get("expires", 0) > now]

    # Group by type
    by_type: Dict[str, int] = {}
    for s in active:
        stype = s.get("type", "unknown")
        by_type[stype] = by_type.get(stype, 0) + 1

    return {
        "total": len(sessions),
        "active": len(active),
        "expired": len(sessions) - len(active),
        "by_type": by_type,
        "timestamp": datetime.now().isoformat()
    }


@router.get("/vouchers")
async def vouchers(user=Depends(require_jwt)):
    """Get all vouchers."""
    all_vouchers = _load(VOUCHERS_FILE, [])
    return {
        "vouchers": all_vouchers,
        "total": len(all_vouchers),
        "unused": sum(1 for v in all_vouchers if not v.get("used")),
        "used": sum(1 for v in all_vouchers if v.get("used"))
    }


@router.get("/vouchers/stats")
async def voucher_stats(user=Depends(require_jwt)):
    """Get voucher statistics."""
    vouchers_list = _load(VOUCHERS_FILE, [])
    now = int(time.time())

    # Recent usage (last 24h)
    cutoff = now - 86400
    recent_used = sum(
        1 for v in vouchers_list
        if v.get("used") and v.get("used_at", 0) > cutoff
    )

    # By prefix
    by_prefix: Dict[str, Dict[str, int]] = {}
    for v in vouchers_list:
        code = v.get("code", "")
        prefix = code.split("-")[0] if "-" in code else "UNKNOWN"
        if prefix not in by_prefix:
            by_prefix[prefix] = {"total": 0, "used": 0}
        by_prefix[prefix]["total"] += 1
        if v.get("used"):
            by_prefix[prefix]["used"] += 1

    return {
        "total": len(vouchers_list),
        "unused": sum(1 for v in vouchers_list if not v.get("used")),
        "used": sum(1 for v in vouchers_list if v.get("used")),
        "used_last_24h": recent_used,
        "by_prefix": by_prefix,
        "timestamp": datetime.now().isoformat()
    }


@router.get("/oauth_providers")
async def oauth_providers(user=Depends(require_jwt)):
    """List OAuth providers."""
    cfg = get_config("oauth")
    providers = []
    for k, v in (cfg or {}).items():
        providers.append({
            "id": k,
            "configured": bool(v.get("client_id")),
            "enabled": v.get("enabled", True)
        })
    return {"providers": providers}


@router.get("/splash_config")
async def splash_config(user=Depends(require_jwt)):
    """Get captive portal splash config."""
    cfg = get_config("auth") or {}
    return {
        "title": cfg.get("splash_title", "SecuBox Guest Access"),
        "logo": cfg.get("splash_logo", "/logo.png"),
        "methods": cfg.get("splash_methods", ["voucher", "oauth"]),
        "welcome_message": cfg.get("welcome_message", "Welcome to SecuBox Network")
    }


@router.get("/bypass_rules")
async def bypass_rules(user=Depends(require_jwt)):
    """Get auth bypass rules."""
    rules_file = Path("/etc/secubox/auth-bypass.json")
    return {"rules": _load(rules_file, [])}


@router.post("/generate_vouchers")
async def generate_vouchers(req: VoucherRequest, user=Depends(require_jwt)):
    """Generate new vouchers."""
    vouchers_list = _load(VOUCHERS_FILE, [])
    new_vouchers = []

    for _ in range(req.count):
        code = f"{req.prefix}-{secrets.token_hex(4).upper()}"
        v = {
            "code": code,
            "duration_hours": req.duration_hours,
            "bandwidth_mb": req.bandwidth_mb,
            "created": int(time.time()),
            "created_at": datetime.now().isoformat(),
            "used": False,
            "created_by": user.get("sub", "unknown")
        }
        vouchers_list.append(v)
        new_vouchers.append(v)

    _save(VOUCHERS_FILE, vouchers_list)
    _record_event("vouchers_generated", {
        "count": len(new_vouchers),
        "prefix": req.prefix,
        "by": user.get("sub")
    })
    stats_cache.clear()

    return {
        "created": len(new_vouchers),
        "vouchers": new_vouchers
    }


@router.post("/redeem_voucher")
async def redeem_voucher(code: str, client_ip: Optional[str] = None):
    """Redeem a voucher (public endpoint)."""
    vouchers_list = _load(VOUCHERS_FILE, [])

    for v in vouchers_list:
        if v["code"] == code and not v.get("used"):
            v["used"] = True
            v["used_at"] = int(time.time())
            v["used_at_iso"] = datetime.now().isoformat()
            v["client_ip"] = client_ip

            _save(VOUCHERS_FILE, vouchers_list)

            # Create session
            sessions = _load(SESSIONS_FILE, [])
            session = {
                "id": secrets.token_hex(8),
                "type": "voucher",
                "voucher_code": code,
                "created": int(time.time()),
                "expires": int(time.time()) + v["duration_hours"] * 3600,
                "client_ip": client_ip,
                "bandwidth_mb": v.get("bandwidth_mb", 0)
            }
            sessions.append(session)
            _save(SESSIONS_FILE, sessions)

            token = create_token(f"voucher:{code}", expires_in=v["duration_hours"] * 3600)

            _record_event("voucher_redeemed", {
                "code": code,
                "client_ip": client_ip,
                "duration_hours": v["duration_hours"]
            })
            await _notify_webhooks("voucher_redeemed", {
                "code": code,
                "client_ip": client_ip
            })
            stats_cache.clear()

            return {
                "success": True,
                "token": token,
                "session_id": session["id"],
                "expires_in": v["duration_hours"] * 3600
            }

    raise HTTPException(400, "Voucher invalide ou déjà utilisé")


@router.get("/validate_voucher")
async def validate_voucher(code: str, user=Depends(require_jwt)):
    """Validate a voucher without consuming it."""
    vouchers_list = _load(VOUCHERS_FILE, [])
    for v in vouchers_list:
        if v["code"] == code:
            return {
                "valid": not v.get("used", False),
                "voucher": v
            }
    return {"valid": False, "error": "Voucher not found"}


@router.post("/delete_voucher")
async def delete_voucher(code: str, user=Depends(require_jwt)):
    """Delete a voucher."""
    vouchers_list = _load(VOUCHERS_FILE, [])
    original_count = len(vouchers_list)
    vouchers_list = [v for v in vouchers_list if v.get("code") != code]

    if len(vouchers_list) < original_count:
        _save(VOUCHERS_FILE, vouchers_list)
        _record_event("voucher_deleted", {"code": code, "by": user.get("sub")})
        stats_cache.clear()
        return {"success": True, "deleted": code}

    return {"success": False, "error": "Voucher not found"}


@router.post("/revoke_session")
async def revoke_session(session_id: str, user=Depends(require_jwt)):
    """Revoke a session."""
    sessions = _load(SESSIONS_FILE, [])
    original_count = len(sessions)
    revoked_session = next((s for s in sessions if s.get("id") == session_id), None)
    sessions = [s for s in sessions if s.get("id") != session_id]

    if len(sessions) < original_count:
        _save(SESSIONS_FILE, sessions)
        _record_event("session_revoked", {
            "session_id": session_id,
            "by": user.get("sub"),
            "session_type": revoked_session.get("type") if revoked_session else "unknown"
        })
        await _notify_webhooks("session_revoked", {"session_id": session_id})
        stats_cache.clear()
        return {"success": True, "revoked": session_id}

    return {"success": False, "error": "Session not found"}


@router.post("/set_provider")
async def set_provider(req: ProviderRequest, user=Depends(require_jwt)):
    """Configure an OAuth provider."""
    _record_event("provider_configured", {
        "provider_id": req.provider_id,
        "by": user.get("sub")
    })
    return {"success": True, "provider": req.provider_id}


@router.post("/delete_provider")
async def delete_provider(provider_id: str, user=Depends(require_jwt)):
    """Delete an OAuth provider."""
    _record_event("provider_deleted", {
        "provider_id": provider_id,
        "by": user.get("sub")
    })
    return {"success": True, "deleted": provider_id}


@router.get("/history")
async def get_history(limit: int = 100, event: Optional[str] = None, user=Depends(require_jwt)):
    """Get event history."""
    history = _load_history()

    if event:
        history = [h for h in history if h.get("event") == event]

    return {
        "events": history[-limit:],
        "total": len(history)
    }


@router.get("/logs")
async def get_logs(lines: int = 100, user=Depends(require_jwt)):
    """Get auth service logs."""
    try:
        r = subprocess.run(
            ["journalctl", "-u", "secubox-auth", "-n", str(min(lines, 500)), "--no-pager"],
            capture_output=True, text=True, timeout=10
        )
        return {"lines": r.stdout.splitlines(), "count": len(r.stdout.splitlines())}
    except Exception as e:
        return {"lines": [], "error": str(e)}


@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    return {"webhooks": _load_webhooks()}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_jwt)):
    """Add a new webhook."""
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@router.get("/summary")
async def summary(user=Depends(require_jwt)):
    """Get auth module summary."""
    now = int(time.time())
    sessions = _load(SESSIONS_FILE, [])
    vouchers_list = _load(VOUCHERS_FILE, [])
    cfg = get_config("oauth")

    active_sessions = [s for s in sessions if s.get("expires", 0) > now]

    # Recent activity (last 24h)
    history = _load_history()
    cutoff = datetime.now() - timedelta(hours=24)
    recent = [
        h for h in history
        if datetime.fromisoformat(h.get("timestamp", "2000-01-01")) > cutoff
    ]

    return {
        "sessions": {
            "active": len(active_sessions),
            "total": len(sessions)
        },
        "vouchers": {
            "total": len(vouchers_list),
            "unused": sum(1 for v in vouchers_list if not v.get("used")),
            "used": sum(1 for v in vouchers_list if v.get("used"))
        },
        "oauth_providers": len(cfg) if cfg else 0,
        "activity_24h": len(recent),
        "recent_events": history[-5:],
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }


# Aliases for compatibility
@router.get("/list_providers")
async def list_providers(user=Depends(require_jwt)):
    return await oauth_providers(user)


@router.get("/list_vouchers")
async def list_vouchers(user=Depends(require_jwt)):
    return await vouchers(user)


@router.post("/create_voucher")
async def create_voucher(
    duration_hours: int = 24,
    bandwidth_mb: int = 0,
    prefix: str = "SBX",
    user=Depends(require_jwt)
):
    req = VoucherRequest(count=1, duration_hours=duration_hours, bandwidth_mb=bandwidth_mb, prefix=prefix)
    result = await generate_vouchers(req, user)
    return result["vouchers"][0] if result["vouchers"] else {}


@router.get("/list_sessions")
async def list_sessions(user=Depends(require_jwt)):
    return await sessions(user)


app.include_router(router)
