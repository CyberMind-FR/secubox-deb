"""SecuBox Portal — Web Authentication & Dashboard

Provides centralized web authentication for all SecuBox modules.
Features:
- JWT token-based authentication
- Session management
- Login/logout endpoints
- Password recovery
- User session tracking
"""
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Response, Cookie
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import jwt

from secubox_core.config import get_config
from secubox_core.logger import get_logger
from secubox_core.auth import create_token as core_create_token

app = FastAPI(title="secubox-portal", version="1.0.0", root_path="/api/v1/portal")
router = APIRouter()
log = get_logger("portal")

# Configuration - use same secret as secubox_core.auth
def _get_jwt_secret() -> str:
    """Get JWT secret - must match secubox_core.auth._secret()"""
    cfg = get_config("api")
    s = cfg.get("jwt_secret", "")
    if not s:
        s = os.environ.get("SECUBOX_JWT_SECRET", "CHANGEME_INSECURE")
    return s

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24
USERS_FILE = Path("/etc/secubox/users.json")

# In-memory session store (would use Redis in production)
_sessions: dict = {}


def _load_users() -> dict:
    """Load users from config file."""
    import json
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text())
    # Default admin user (password: secubox)
    return {
        "admin": {
            "password_hash": hashlib.sha256("secubox".encode()).hexdigest(),
            "email": "admin@secubox.local",
            "role": "admin",
            "created": datetime.now().isoformat()
        }
    }


def _save_users(users: dict):
    """Save users to config file."""
    import json
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2))


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


# ══════════════════════════════════════════════════════════════════
# PUBLIC ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@router.get("/status")
async def status():
    """Portal status (public)."""
    return {
        "module": "portal",
        "version": "1.0.0",
        "auth_required": True,
        "active_sessions": len(_sessions),
    }


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(req: LoginRequest, response: Response):
    """Authenticate user and return JWT token."""
    users = _load_users()

    if req.username not in users:
        log.warning("Login failed: unknown user %s", req.username)
        raise HTTPException(401, "Identifiants invalides")

    user = users[req.username]
    password_hash = hashlib.sha256(req.password.encode()).hexdigest()

    if user["password_hash"] != password_hash:
        log.warning("Login failed: wrong password for %s", req.username)
        raise HTTPException(401, "Identifiants invalides")

    # Create token
    token = _create_token(req.username, user.get("role", "user"))

    # Store session
    _sessions[req.username] = {
        "login_time": datetime.now().isoformat(),
        "ip": "local",  # Would get from request in production
    }

    # Set cookie
    response.set_cookie(
        key="secubox_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=JWT_EXPIRE_HOURS * 3600
    )

    log.info("User %s logged in successfully", req.username)

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
    if secubox_token:
        payload = _verify_token(secubox_token)
        if payload:
            username = payload.get("sub")
            if username in _sessions:
                del _sessions[username]
                log.info("User %s logged out", username)

    response.delete_cookie("secubox_token")
    return {"success": True, "message": "Deconnecte"}


@router.get("/verify")
async def verify(secubox_token: Optional[str] = Cookie(None)):
    """Verify current session."""
    if not secubox_token:
        return {"valid": False, "error": "No token"}

    payload = _verify_token(secubox_token)
    if not payload:
        return {"valid": False, "error": "Invalid or expired token"}

    return {
        "valid": True,
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "expires": payload.get("exp"),
    }


class RecoverRequest(BaseModel):
    email: str


@router.post("/recover")
async def recover(req: RecoverRequest):
    """Send password recovery email (placeholder)."""
    # In production, would send actual email
    log.info("Password recovery requested for %s", req.email)
    return {
        "success": True,
        "message": "Si ce compte existe, un email a ete envoye."
    }


# ══════════════════════════════════════════════════════════════════
# PROTECTED ENDPOINTS
# ══════════════════════════════════════════════════════════════════

def require_auth(secubox_token: Optional[str] = Cookie(None)):
    """Dependency to require authentication."""
    if not secubox_token:
        raise HTTPException(401, "Authentification requise")

    payload = _verify_token(secubox_token)
    if not payload:
        raise HTTPException(401, "Session expiree ou invalide")

    return payload


@router.get("/sessions")
async def sessions(user=Depends(require_auth)):
    """List active sessions (admin only)."""
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin requis")

    return {"sessions": _sessions}


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
                "created": d.get("created")
            }
            for u, d in users.items()
        ]
    }


class CreateUserRequest(BaseModel):
    username: str
    password: str
    email: str
    role: str = "user"


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
        "created": datetime.now().isoformat()
    }

    _save_users(users)
    log.info("User %s created by %s", req.username, user.get("sub"))

    return {"success": True, "username": req.username}


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


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
    _save_users(users)

    log.info("Password changed for %s", username)
    return {"success": True}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "portal"}


app.include_router(router)
