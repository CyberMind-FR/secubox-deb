"""
secubox_core.auth — JWT HS256 authentication
=============================================
- create_token(username) → str
- require_jwt            → FastAPI dependency
- router                 → /auth/login endpoint
"""
from __future__ import annotations
import os, time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

from .config import get_config
from .logger import get_logger

log = get_logger("auth")

# auto_error=False allows us to handle missing token gracefully
_bearer = HTTPBearer(auto_error=False)

# Session event callback (set by auth module to record sessions)
_session_callback = None

def set_session_callback(callback):
    """Set callback function for session events: callback(event, username, details)"""
    global _session_callback
    _session_callback = callback

def _emit_session_event(event: str, username: str, details: dict = None):
    """Emit session event to callback if set."""
    if _session_callback:
        try:
            _session_callback(event, username, details or {})
        except Exception as e:
            log.warning("Session callback error: %s", e)

# ── JWT helpers ────────────────────────────────────────────────────

def _secret() -> str:
    """Lit le secret JWT depuis la config (généré au firstboot)."""
    cfg = get_config("api")
    s = cfg.get("jwt_secret", "")
    if not s:
        # Fallback : variable d'environnement (dev/test)
        s = os.environ.get("SECUBOX_JWT_SECRET", "CHANGEME_INSECURE")
    return s


def create_token(username: str, expires_in: int = 86400) -> str:
    """Crée un JWT HS256 valide `expires_in` secondes."""
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in,
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def _decode_token(token: str) -> dict:
    """Décode et valide le JWT. Lève HTTPException si invalide."""
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
        if payload.get("sub") is None:
            raise ValueError("missing sub")
        return payload
    except JWTError as exc:
        log.warning("JWT invalide: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_jwt(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)
) -> dict:
    """Dependency FastAPI — injecter dans tous les endpoints protégés."""
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Bearer manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _decode_token(creds.credentials)


# ── Login endpoint ─────────────────────────────────────────────────

router = APIRouter(tags=["auth"])  # No prefix - let the app decide


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400


def _check_password(username: str, password: str) -> bool:
    """
    Vérifie les credentials depuis /etc/secubox/users.toml.
    Format :
        [users.admin]
        password_hash = "<bcrypt>"   # à implémenter
    Pour l'instant : lecture d'un mot de passe en clair depuis la config.
    TODO : remplacer par bcrypt + adduser secubox-admin.
    """
    cfg = get_config("auth")
    users = cfg.get("users", {})
    user = users.get(username, {})
    expected = user.get("password", "")
    # Comparaison simple — remplacer par bcrypt en production
    return expected and password == expected


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request):
    """Endpoint de login — retourne un JWT."""
    # Extract client info for session tracking
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.headers.get("X-Real-IP", "")
    if not client_ip and request.client:
        client_ip = request.client.host
    user_agent = request.headers.get("User-Agent", "")

    if not _check_password(req.username, req.password):
        log.warning("Échec login: %s from %s", req.username, client_ip)
        _emit_session_event("login_failed", req.username, {
            "reason": "invalid_credentials",
            "ip": client_ip,
            "user_agent": user_agent[:100] if user_agent else ""
        })
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
        )
    token = create_token(req.username)
    log.info("Login OK: %s from %s", req.username, client_ip)
    _emit_session_event("login_success", req.username, {
        "expires_in": 86400,
        "ip": client_ip,
        "user_agent": user_agent[:100] if user_agent else ""
    })
    return TokenResponse(access_token=token)
