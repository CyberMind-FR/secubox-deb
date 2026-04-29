"""SecuBox Portal - Web Authentication & Dashboard with Enhanced Monitoring

Provides centralized web authentication for all SecuBox modules.
Features:
- JWT token-based authentication
- Session management with tracking
- Login/logout with history
- Password recovery
- User management
- Webhooks for auth events
"""
import os
import hashlib
import secrets
import json
import threading
import time
import asyncio
import hmac
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Response, Cookie, Request
from pydantic import BaseModel, Field, validator
import jwt

from secubox_core.config import get_config
from secubox_core.logger import get_logger
from secubox_core.auth import create_token as core_create_token
from secubox_core.kiosk import (
    detect_board_type, get_board_profile, get_board_capabilities, get_board_model
)

app = FastAPI(title="secubox-portal", version="2.1.0", root_path="/api/v1/portal")
router = APIRouter()
log = get_logger("portal")

# Configuration
DATA_DIR = Path("/var/lib/secubox/portal")
DATA_DIR.mkdir(parents=True, exist_ok=True)
USERS_FILE = Path("/etc/secubox/users.json")
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats.json"

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24

# In-memory session store with metadata
_sessions: Dict[str, Dict[str, Any]] = {}


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
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1)


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=6)
    email: str
    role: str = "user"


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)


class RecoverRequest(BaseModel):
    email: str


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["login", "logout", "login_failed", "user_created"])
    secret: Optional[str] = None
    enabled: bool = True

    @validator("url")
    def validate_url(cls, v):
        """Validate URL format (Pydantic v1 compatible)."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# State
_cleanup_task: Optional[asyncio.Task] = None


def _get_jwt_secret() -> str:
    """Get JWT secret - must match secubox_core.auth._secret()"""
    cfg = get_config("api")
    s = cfg.get("jwt_secret", "") if cfg else ""
    if not s:
        s = os.environ.get("SECUBOX_JWT_SECRET", "CHANGEME_INSECURE")
    return s


def _load_json(filepath: Path, default=None):
    """Load JSON file safely."""
    if filepath.exists():
        try:
            return json.loads(filepath.read_text())
        except Exception:
            pass
    return default if default is not None else []


def _save_json(filepath: Path, data):
    """Save JSON file safely."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(json.dumps(data, indent=2))


def _load_users() -> dict:
    """Load users from config file, creating default if missing."""
    if USERS_FILE.exists():
        try:
            return json.loads(USERS_FILE.read_text())
        except (json.JSONDecodeError, IOError) as e:
            log.error("Failed to load users.json: %s", e)

    default_users = {
        "admin": {
            "password_hash": hashlib.sha256("secubox".encode()).hexdigest(),
            "email": "admin@secubox.local",
            "role": "admin",
            "created": datetime.now().isoformat()
        }
    }
    _save_users(default_users)
    log.info("Created default admin user (password: secubox)")
    return default_users


def _save_users(users: dict):
    """Save users to config file."""
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2))


def _load_history() -> List[Dict[str, Any]]:
    return _load_json(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-2000:]
    _save_json(HISTORY_FILE, history)


def _load_webhooks() -> List[Dict[str, Any]]:
    return _load_json(WEBHOOKS_FILE, [])


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    _save_json(WEBHOOKS_FILE, webhooks)


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


def _create_token(username: str, role: str = "user") -> str:
    """Create JWT token using shared secret."""
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
        "jti": secrets.token_hex(16)
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm=JWT_ALGORITHM)


def _verify_token(token: str) -> Optional[dict]:
    """Verify and decode JWT token using shared secret."""
    try:
        payload = jwt.decode(token, _get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(secubox_token: Optional[str] = Cookie(None)):
    """Dependency to require authentication."""
    if not secubox_token:
        raise HTTPException(401, "Authentification requise")

    payload = _verify_token(secubox_token)
    if not payload:
        raise HTTPException(401, "Session expiree ou invalide")

    return payload


async def _cleanup_expired_sessions():
    """Background task to clean up expired sessions."""
    while True:
        try:
            now = datetime.now()
            expired = []

            for username, session in list(_sessions.items()):
                try:
                    login_time = datetime.fromisoformat(session.get("login_time", ""))
                    if now - login_time > timedelta(hours=JWT_EXPIRE_HOURS):
                        expired.append(username)
                except ValueError:
                    expired.append(username)

            for username in expired:
                del _sessions[username]
                _record_event("session_expired", {"username": username})

        except Exception:
            pass

        await asyncio.sleep(300)


@app.on_event("startup")
async def startup_init():
    """Initialize portal on startup."""
    global _cleanup_task
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    users = _load_users()
    log.info("Portal started with %d users", len(users))
    _cleanup_task = asyncio.create_task(_cleanup_expired_sessions())


@app.on_event("shutdown")
async def shutdown():
    """Stop background tasks."""
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()


# ══════════════════════════════════════════════════════════════════
# Device-Specific Theming
# ══════════════════════════════════════════════════════════════════

BOARD_THEMES = {
    "mochabin": {
        "name": "Pro",
        "description": "Professional theme for MOCHAbin (Armada 7040)",
        "logo_text": "SecuBox Pro",
        "logo_sub": "Enterprise Security Appliance",
        "colors": {
            "accent": "#0ea5e9",        # Sky blue
            "accent_glow": "rgba(14,165,233,0.2)",
            "accent_dark": "#0284c7",
            "gradient_start": "#0ea5e9",
            "gradient_end": "#0369a1",
            "success": "#22c55e",
            "warning": "#f59e0b",
            "error": "#ef4444",
        },
        "logo_icon": "S",
        "badge": "PRO",
    },
    "espressobin-v7": {
        "name": "Lite",
        "description": "Compact theme for ESPRESSObin (Armada 3720)",
        "logo_text": "SecuBox Lite",
        "logo_sub": "Compact Network Security",
        "colors": {
            "accent": "#22c55e",         # Green
            "accent_glow": "rgba(34,197,94,0.2)",
            "accent_dark": "#16a34a",
            "gradient_start": "#22c55e",
            "gradient_end": "#15803d",
            "success": "#22c55e",
            "warning": "#eab308",
            "error": "#dc2626",
        },
        "logo_icon": "S",
        "badge": "LITE",
    },
    "espressobin-ultra": {
        "name": "Ultra",
        "description": "Enhanced theme for ESPRESSObin Ultra",
        "logo_text": "SecuBox Ultra",
        "logo_sub": "Enhanced Compact Security",
        "colors": {
            "accent": "#14b8a6",         # Teal
            "accent_glow": "rgba(20,184,166,0.2)",
            "accent_dark": "#0d9488",
            "gradient_start": "#14b8a6",
            "gradient_end": "#0f766e",
            "success": "#22c55e",
            "warning": "#f59e0b",
            "error": "#ef4444",
        },
        "logo_icon": "S",
        "badge": "ULTRA",
    },
    "x64-vm": {
        "name": "Virtual",
        "description": "Virtual machine theme",
        "logo_text": "SecuBox VM",
        "logo_sub": "Virtual Security Appliance",
        "colors": {
            "accent": "#8b5cf6",          # Purple
            "accent_glow": "rgba(139,92,246,0.2)",
            "accent_dark": "#7c3aed",
            "gradient_start": "#8b5cf6",
            "gradient_end": "#6d28d9",
            "success": "#22c55e",
            "warning": "#f59e0b",
            "error": "#ef4444",
        },
        "logo_icon": "V",
        "badge": "VM",
    },
    "x64-baremetal": {
        "name": "Server",
        "description": "Bare-metal server theme",
        "logo_text": "SecuBox Server",
        "logo_sub": "Bare-Metal Security Platform",
        "colors": {
            "accent": "#f97316",          # Orange
            "accent_glow": "rgba(249,115,22,0.2)",
            "accent_dark": "#ea580c",
            "gradient_start": "#f97316",
            "gradient_end": "#c2410c",
            "success": "#22c55e",
            "warning": "#fbbf24",
            "error": "#dc2626",
        },
        "logo_icon": "S",
        "badge": "SERVER",
    },
    "rpi": {
        "name": "Maker",
        "description": "Raspberry Pi maker theme",
        "logo_text": "SecuBox Pi",
        "logo_sub": "Maker Security Device",
        "colors": {
            "accent": "#ec4899",          # Pink (Raspberry)
            "accent_glow": "rgba(236,72,153,0.2)",
            "accent_dark": "#db2777",
            "gradient_start": "#ec4899",
            "gradient_end": "#be185d",
            "success": "#22c55e",
            "warning": "#f59e0b",
            "error": "#ef4444",
        },
        "logo_icon": "Pi",
        "badge": "PI",
    },
    "unknown": {
        "name": "Standard",
        "description": "Default SecuBox theme",
        "logo_text": "SecuBox",
        "logo_sub": "Secure Network Appliance",
        "colors": {
            "accent": "#58a6ff",          # Blue (default)
            "accent_glow": "rgba(88,166,255,0.2)",
            "accent_dark": "#1f6feb",
            "gradient_start": "#58a6ff",
            "gradient_end": "#1f6feb",
            "success": "#3fb950",
            "warning": "#d29922",
            "error": "#f85149",
        },
        "logo_icon": "S",
        "badge": None,
    },
}


@router.get("/theme")
async def get_theme():
    """
    Get device-specific theme based on detected board type.
    Returns theme colors, logo text, and board info.
    Public endpoint - used by login page and all UI components.
    """
    board_type = detect_board_type()
    profile = get_board_profile(board_type)
    model = get_board_model()

    # Get theme for this board, fallback to unknown
    theme = BOARD_THEMES.get(board_type, BOARD_THEMES["unknown"])

    return {
        "board_type": board_type,
        "board_model": model,
        "profile": profile,
        "theme": theme,
        "css_vars": _generate_css_vars(theme["colors"]),
    }


def _generate_css_vars(colors: dict) -> str:
    """Generate CSS custom properties string from colors dict."""
    css_lines = []
    for key, value in colors.items():
        css_name = f"--{key.replace('_', '-')}"
        css_lines.append(f"{css_name}: {value};")
    return "\n".join(css_lines)


@router.get("/branding")
async def get_branding():
    """
    Get full branding info including theme, capabilities, and display settings.
    """
    board_type = detect_board_type()
    profile = get_board_profile(board_type)
    caps = get_board_capabilities(board_type)
    model = get_board_model()
    theme = BOARD_THEMES.get(board_type, BOARD_THEMES["unknown"])

    return {
        "board": {
            "type": board_type,
            "model": model,
            "profile": profile,
            "capabilities": caps,
        },
        "branding": {
            "logo_text": theme["logo_text"],
            "logo_sub": theme["logo_sub"],
            "logo_icon": theme["logo_icon"],
            "badge": theme["badge"],
            "theme_name": theme["name"],
        },
        "colors": theme["colors"],
        "css_vars": _generate_css_vars(theme["colors"]),
    }


# Public endpoints
@router.get("/health")
async def health():
    return {"status": "ok", "module": "portal", "version": "2.1.0"}


@router.get("/status")
async def status():
    """Portal status (public)."""
    users = _load_users()
    return {
        "module": "portal",
        "version": "2.0.0",
        "auth_required": True,
        "active_sessions": len(_sessions),
        "total_users": len(users),
        "timestamp": datetime.now().isoformat()
    }


@router.post("/login")
async def login(req: LoginRequest, response: Response, request: Request):
    """Authenticate user and return JWT token."""
    users = _load_users()
    client_ip = request.client.host if request.client else "unknown"

    if req.username not in users:
        log.warning("Login failed: unknown user %s from %s", req.username, client_ip)
        _record_event("login_failed", {"username": req.username, "reason": "unknown_user", "ip": client_ip})
        await _notify_webhooks("login_failed", {"username": req.username, "ip": client_ip})
        raise HTTPException(401, "Identifiants invalides")

    user = users[req.username]
    password_hash = hashlib.sha256(req.password.encode()).hexdigest()

    if user["password_hash"] != password_hash:
        log.warning("Login failed: wrong password for %s from %s", req.username, client_ip)
        _record_event("login_failed", {"username": req.username, "reason": "wrong_password", "ip": client_ip})
        await _notify_webhooks("login_failed", {"username": req.username, "ip": client_ip})
        raise HTTPException(401, "Identifiants invalides")

    token = _create_token(req.username, user.get("role", "user"))

    _sessions[req.username] = {
        "login_time": datetime.now().isoformat(),
        "ip": client_ip,
        "role": user.get("role", "user"),
        "user_agent": request.headers.get("user-agent", "")[:100]
    }

    response.set_cookie(
        key="secubox_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=JWT_EXPIRE_HOURS * 3600
    )

    log.info("User %s logged in from %s", req.username, client_ip)
    _record_event("login", {"username": req.username, "ip": client_ip, "role": user.get("role")})
    await _notify_webhooks("login", {"username": req.username, "ip": client_ip})
    stats_cache.clear()

    return {
        "success": True,
        "token": token,
        "username": req.username,
        "email": user.get("email", ""),
        "role": user.get("role", "user"),
        "expires_in": JWT_EXPIRE_HOURS * 3600,
    }


@router.post("/logout")
async def logout(response: Response, secubox_token: Optional[str] = Cookie(None)):
    """Logout and invalidate session."""
    username = None
    if secubox_token:
        payload = _verify_token(secubox_token)
        if payload:
            username = payload.get("sub")
            if username in _sessions:
                del _sessions[username]

    response.delete_cookie("secubox_token")

    if username:
        log.info("User %s logged out", username)
        _record_event("logout", {"username": username})
        await _notify_webhooks("logout", {"username": username})
        stats_cache.clear()

    return {"success": True, "message": "Deconnecte"}


@router.get("/verify")
async def verify(secubox_token: Optional[str] = Cookie(None)):
    """Verify current session."""
    if not secubox_token:
        return {"valid": False, "error": "No token"}

    payload = _verify_token(secubox_token)
    if not payload:
        return {"valid": False, "error": "Invalid or expired token"}

    username = payload.get("sub")
    session = _sessions.get(username, {})

    return {
        "valid": True,
        "username": username,
        "role": payload.get("role"),
        "expires": payload.get("exp"),
        "session": {
            "login_time": session.get("login_time"),
            "ip": session.get("ip")
        }
    }


@router.post("/recover")
async def recover(req: RecoverRequest):
    """Send password recovery email (placeholder)."""
    log.info("Password recovery requested for %s", req.email)
    _record_event("password_recovery_requested", {"email": req.email})
    return {
        "success": True,
        "message": "Si ce compte existe, un email a ete envoye."
    }


# Protected endpoints
@router.get("/sessions")
async def sessions(user=Depends(require_auth)):
    """List active sessions (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    session_list = []
    for username, session in _sessions.items():
        session_list.append({
            "username": username,
            **session
        })

    return {
        "sessions": session_list,
        "count": len(session_list)
    }


@router.delete("/sessions/{username}")
async def revoke_session(username: str, user=Depends(require_auth)):
    """Revoke a user's session (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    if username in _sessions:
        del _sessions[username]
        _record_event("session_revoked", {"username": username, "by": user.get("sub")})
        stats_cache.clear()
        return {"success": True, "revoked": username}

    return {"success": False, "error": "Session not found"}


@router.get("/users")
async def list_users(user=Depends(require_auth)):
    """List users (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    users = _load_users()
    return {
        "users": [
            {
                "username": u,
                "email": d.get("email"),
                "role": d.get("role", "user"),
                "created": d.get("created"),
                "active": u in _sessions
            }
            for u, d in users.items()
        ],
        "count": len(users)
    }


@router.post("/users/create")
async def create_user(req: CreateUserRequest, user=Depends(require_auth)):
    """Create new user (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    users = _load_users()

    if req.username in users:
        raise HTTPException(400, "Utilisateur existe deja")

    users[req.username] = {
        "password_hash": hashlib.sha256(req.password.encode()).hexdigest(),
        "email": req.email,
        "role": req.role,
        "created": datetime.now().isoformat(),
        "created_by": user.get("sub")
    }

    _save_users(users)
    log.info("User %s created by %s", req.username, user.get("sub"))
    _record_event("user_created", {"username": req.username, "role": req.role, "by": user.get("sub")})
    await _notify_webhooks("user_created", {"username": req.username, "role": req.role})
    stats_cache.clear()

    return {"success": True, "username": req.username}


@router.delete("/users/{username}")
async def delete_user(username: str, user=Depends(require_auth)):
    """Delete a user (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    if username == user.get("sub"):
        raise HTTPException(400, "Cannot delete yourself")

    users = _load_users()
    if username not in users:
        raise HTTPException(404, "User not found")

    del users[username]
    _save_users(users)

    if username in _sessions:
        del _sessions[username]

    log.info("User %s deleted by %s", username, user.get("sub"))
    _record_event("user_deleted", {"username": username, "by": user.get("sub")})
    stats_cache.clear()

    return {"success": True, "deleted": username}


@router.post("/users/change-password")
async def change_password(req: ChangePasswordRequest, user=Depends(require_auth)):
    """Change own password."""
    username = user.get("sub")
    users = _load_users()

    if username not in users:
        raise HTTPException(404, "Utilisateur non trouve")

    old_hash = hashlib.sha256(req.old_password.encode()).hexdigest()
    if users[username]["password_hash"] != old_hash:
        raise HTTPException(401, "Mot de passe actuel incorrect")

    users[username]["password_hash"] = hashlib.sha256(req.new_password.encode()).hexdigest()
    users[username]["password_changed"] = datetime.now().isoformat()
    _save_users(users)

    log.info("Password changed for %s", username)
    _record_event("password_changed", {"username": username})

    return {"success": True}


@router.get("/history")
async def get_history(limit: int = 100, event: Optional[str] = None, user=Depends(require_auth)):
    """Get authentication history (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    history = _load_history()

    if event:
        history = [h for h in history if h.get("event") == event]

    return {
        "events": history[-limit:],
        "total": len(history)
    }


@router.get("/stats")
async def get_stats(user=Depends(require_auth)):
    """Get authentication statistics (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    history = _load_history()
    users = _load_users()

    # Last 24h stats
    cutoff = datetime.now() - timedelta(hours=24)
    recent = [
        h for h in history
        if datetime.fromisoformat(h.get("timestamp", "2000-01-01")) > cutoff
    ]

    by_event: Dict[str, int] = {}
    for h in recent:
        event = h.get("event", "unknown")
        by_event[event] = by_event.get(event, 0) + 1

    return {
        "total_users": len(users),
        "active_sessions": len(_sessions),
        "events_24h": len(recent),
        "by_event_24h": by_event,
        "logins_24h": by_event.get("login", 0),
        "failed_logins_24h": by_event.get("login_failed", 0),
        "timestamp": datetime.now().isoformat()
    }


# Webhooks
@router.get("/webhooks")
async def list_webhooks(user=Depends(require_auth)):
    """List configured webhooks (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")
    return {"webhooks": _load_webhooks()}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_auth)):
    """Add a new webhook (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_auth)):
    """Delete a webhook (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@router.get("/summary")
async def summary():
    """Get portal summary."""
    users = _load_users()
    history = _load_history()

    # Recent activity
    cutoff = datetime.now() - timedelta(hours=24)
    recent_logins = sum(
        1 for h in history
        if h.get("event") == "login" and
        datetime.fromisoformat(h.get("timestamp", "2000-01-01")) > cutoff
    )

    return {
        "users": {
            "total": len(users),
            "admins": sum(1 for u in users.values() if u.get("role") == "admin"),
            "regular": sum(1 for u in users.values() if u.get("role") != "admin")
        },
        "sessions": {
            "active": len(_sessions),
            "users_online": list(_sessions.keys())[:10]
        },
        "activity_24h": {
            "logins": recent_logins
        },
        "webhooks_configured": len(_load_webhooks()),
        "recent_events": history[-5:],
        "timestamp": datetime.now().isoformat()
    }


app.include_router(router)
