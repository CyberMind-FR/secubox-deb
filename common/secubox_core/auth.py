"""SecuBox core auth — JWT HS256 over a `user_store`-backed identity.

Compared to v1 (plaintext `auth.toml` lookup), this module:
- delegates password verification to `secubox_core.user_store`
- adds a `jti` claim to every issued token
- validates the `jti` against an externally-injected session validator
- carries an optional `scope` claim for short-lived setup / mfa / enroll tokens
- defensively re-checks `is_enabled` on every authenticated request
"""
from __future__ import annotations

import os
import secrets
import time
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

from . import user_store
from .config import get_config
from .logger import get_logger

log = get_logger("auth")
_bearer = HTTPBearer(auto_error=False)

# Session callbacks ─────────────────────────────────────────────────────
_session_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None
_session_validator: Callable[[str], bool] = lambda jti: True


def set_session_callback(cb: Callable[[str, str, Dict[str, Any]], None]) -> None:
    """Set callback fired on login_success / login_failed / etc."""
    global _session_callback
    _session_callback = cb


def set_session_validator(fn: Callable[[str], bool]) -> None:
    """Inject the jti → bool checker used by require_jwt."""
    global _session_validator
    _session_validator = fn


def _emit_session_event(event: str, username: str, details: Optional[Dict[str, Any]] = None) -> None:
    if _session_callback:
        try:
            _session_callback(event, username, details or {})
        except Exception as exc:
            log.warning("session callback error: %s", exc)


# JWT helpers ────────────────────────────────────────────────────────────
def _secret() -> str:
    cfg = get_config("api")
    s = cfg.get("jwt_secret", "")
    if not s:
        s = os.environ.get("SECUBOX_JWT_SECRET", "CHANGEME_INSECURE")
    return s


# SSO-lite (#400) ────────────────────────────────────────────────────────
# A session cookie + /verify endpoint let nginx `auth_request` gate vhosts
# against SecuBox users directly — replacing Authelia while reusing the same
# argon2 user_store. The cookie is set parent-domain-scoped so one login
# covers every *.<domain> vhost (SSO-lite). Configure the parent domain via
# api.sso_cookie_domain in secubox.conf (e.g. ".gk2.secubox.in"); empty =
# host-only cookie (still works, but not shared across subdomains).
SESSION_COOKIE = "secubox_session"


def _cookie_domain() -> Optional[str]:
    cfg = get_config("api")
    dom = cfg.get("sso_cookie_domain", "") or os.environ.get("SECUBOX_SSO_COOKIE_DOMAIN", "")
    return dom or None


def set_session_cookie(response: Response, token: str, expires_in: int = 86400) -> None:
    """Public helper so override modules (secubox-auth) emit the same SSO-lite
    session cookie on their own login-success paths."""
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=expires_in,
        httponly=True,
        secure=True,
        samesite="lax",
        domain=_cookie_domain(),
        path="/",
    )


def create_token(
    username: str,
    expires_in: int = 86400,
    scope: Optional[str] = None,
    jti: Optional[str] = None,
) -> str:
    """Mint a JWT. `scope` carries a short-lived intent ("set-password", "mfa-challenge", …)."""
    payload: Dict[str, Any] = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in,
        "jti": jti or secrets.token_hex(8),
    }
    if scope:
        payload["scope"] = scope
    return jwt.encode(payload, _secret(), algorithm="HS256")


def _decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
        if not payload.get("sub"):
            raise ValueError("missing sub")
        return payload
    except (JWTError, ValueError) as exc:
        log.warning("JWT invalide: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _validate_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode + session/enabled checks. Returns the payload if the token is
    fully valid, else None — never raises. Used to try multiple credential
    sources (Bearer, cookie) without the first failure aborting the request."""
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
    except JWTError:
        return None
    if not payload.get("sub"):
        return None
    jti = payload.get("jti")
    if not jti or not _session_validator(jti):
        return None
    if not user_store.is_enabled(payload["sub"]):
        return None
    return payload


async def require_jwt(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Dict[str, Any]:
    # SSO-lite (#400): accept the Bearer token OR the parent-domain session
    # cookie. The cookie lets one SecuBox login cover every module without
    # re-auth (SameSite=Lax, CSRF-mitigated).
    #
    # Shadowing fix: try BOTH sources, Bearer first then cookie, and accept the
    # first that fully validates. Previously a present-but-STALE Bearer (an old
    # localStorage sbx_token the webui still sent) was used exclusively and its
    # failure 401'd the request even when the session cookie was perfectly
    # valid — which hard-redirected the panel to /login.html in a loop. A stale
    # token must never shadow a live session.
    candidates = []
    if creds is not None and creds.credentials:
        candidates.append(creds.credentials)
    cookie_tok = request.cookies.get(SESSION_COOKIE)
    if cookie_tok:
        candidates.append(cookie_tok)
    if not candidates:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Bearer ou session manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )
    for token in candidates:
        payload = _validate_token(token)
        if payload is not None:
            return payload
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )


# Password verification ─────────────────────────────────────────────────
def _check_password(username: str, password: str) -> bool:
    """Delegate to user_store. Replaces the old plaintext auth.toml lookup."""
    return user_store.verify_password(username, password)


# Legacy /auth/login endpoint kept for backwards compat ────────────────
router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request, response: Response):
    """Plain login endpoint — secubox-auth overrides this with the full branching flow."""
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() \
        or request.headers.get("X-Real-IP", "") \
        or (request.client.host if request.client else "")
    user_agent = request.headers.get("User-Agent", "")
    if not _check_password(req.username, req.password):
        _emit_session_event("login_failed", req.username, {
            "reason": "invalid_credentials",
            "ip": client_ip,
            "user_agent": user_agent[:100] if user_agent else "",
        })
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
        )
    jti = secrets.token_hex(8)
    tok = create_token(req.username, jti=jti)
    # SSO-lite: also drop a parent-domain session cookie so nginx auth_request
    # (GET /auth/verify) gates sibling vhosts with this one login.
    set_session_cookie(response, tok)
    _emit_session_event("login_success", req.username, {
        "jti": jti,
        "expires_in": 86400,
        "ip": client_ip,
        "user_agent": user_agent[:100] if user_agent else "",
    })
    return TokenResponse(access_token=tok)


@router.get("/verify")
async def verify(request: Request):
    """nginx `auth_request` target (SSO-lite, #400).

    Validates the SecuBox session cookie (or a Bearer token for API clients)
    against the same checks as require_jwt, and echoes the identity back as
    `Remote-User` / `Remote-Groups` headers for the proxied app. 200 = allow,
    401 = deny (nginx then 302s to the SecuBox login page)."""
    tok = request.cookies.get(SESSION_COOKIE)
    if not tok:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth[7:]
    if not tok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="no session")
    # _decode_token raises 401 on invalid/expired.
    payload = _decode_token(tok)
    jti = payload.get("jti")
    if not jti or not _session_validator(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session révoquée")
    sub = payload["sub"]
    if not user_store.is_enabled(sub):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="compte désactivé")
    role = ""
    try:
        getter = getattr(user_store, "get_user", None)
        if callable(getter):
            u = getter(sub) or {}
            role = u.get("role", "") if isinstance(u, dict) else ""
    except Exception:
        role = ""
    return JSONResponse(
        {"ok": True, "user": sub},
        headers={"Remote-User": sub, "Remote-Groups": role},
    )


@router.post("/logout")
async def logout(response: Response):
    """Clear the SSO-lite session cookie."""
    response.delete_cookie(SESSION_COOKIE, domain=_cookie_domain(), path="/")
    return {"ok": True}
