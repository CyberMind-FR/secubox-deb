# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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

from . import sessions as _sessions
from . import user_store
from .config import get_config
from .logger import get_logger

log = get_logger("auth")
_bearer = HTTPBearer(auto_error=False)

# Session callbacks ─────────────────────────────────────────────────────
_session_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None

# Default validator — FAIL-CLOSED since #942.
#
# It used to be `lambda jti: True`. Only `secubox-auth` ever calls
# `set_session_validator()`, so every module served on its own socket (44 of
# them on gk2) accepted revoked sessions forever, and the 116 mounted in the
# aggregator were covered only by the side effect of `auth` being imported
# into the same interpreter — a protection that silently vanished whenever
# that import failed.
#
# The shared read-only store answers the same question without an IPC hop.
# `secubox-auth` still overrides this with its own writer-side validator.
_session_validator: Callable[[str], bool] = _sessions.is_valid



def _samesite(secure: bool) -> str:
    """Politique SameSite d'un cookie SecuBox. Voir #1251."""
    force = os.environ.get("SECUBOX_COOKIE_SAMESITE", "").strip().lower()
    if force in ("lax", "strict", "none"):
        return force
    return "none" if secure else "lax"

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
    """The HS256 signing secret. Raises when unset — never signs with a default.

    Until #942 this fell back to a hard-coded placeholder, so a node whose
    config had not been provisioned would boot happily and sign every token
    in the fleet with a string published in the source tree. A missing secret
    is a provisioning failure and must stop the service, not degrade it.
    """
    try:
        cfg = get_config("api")
    except OSError as exc:
        # Unreadable config is not a reason to fall back to a weaker secret;
        # try the environment, then fail.
        log.warning("config unreadable while reading jwt_secret: %s", exc)
        cfg = {}
    s = cfg.get("jwt_secret", "") or os.environ.get("SECUBOX_JWT_SECRET", "")
    if not s:
        raise RuntimeError(
            "jwt_secret is not configured: set api.jwt_secret in "
            "/etc/secubox/secubox.conf or SECUBOX_JWT_SECRET in the unit. "
            "Refusing to sign tokens with a default."
        )
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
        # Encadre par le Hall, un service est un contexte TIERS : le
        # navigateur rejette un cookie Lax ou Strict pose la, et le service
        # ne reconnait plus le visiteur (#1251). None exige Secure ; en clair
        # on retombe sur Lax plutot que de poser un cookie que le navigateur
        # jettera. SECUBOX_COOKIE_SAMESITE ferme la porte si l'operateur le
        # veut, au prix de l'affichage encadre.
        samesite=_samesite(True),   # secure=True juste au-dessus
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


def _is_scope_token(payload: Dict[str, Any]) -> bool:
    """A `scope` claim marks an INTENT token, never an access token (#942).

    `create_token(scope=...)` mints three of them: `mfa-challenge` (issued
    after the password check but BEFORE the TOTP check), `set-password`
    (issued against an EMPTY password when must_change_password is set) and
    `totp-enroll`. `_validate_token` never looked at the claim, so any of
    them opened a full session on every module keeping the permissive
    validator — a 2FA bypass with the password alone, and a passwordless
    entry for a freshly provisioned account.

    They are redeemed by `secubox-auth`'s own `_check_scope()`, which
    verifies the exact expected scope. They must never reach `require_jwt`.
    """
    return bool(payload.get("scope"))


def _validate_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode + scope/session/enabled checks. Returns the payload if the token
    is fully valid, else None — never raises. Used to try multiple credential
    sources (Bearer, cookie) without the first failure aborting the request."""
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
    except JWTError:
        return None
    if not payload.get("sub"):
        return None
    if _is_scope_token(payload):
        log.warning(
            "rejected scope token (scope=%s, sub=%s) presented as an access token",
            payload.get("scope"), payload.get("sub"),
        )
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
    # Same rule as require_jwt (#942): an intent token is not a session.
    if _is_scope_token(payload):
        log.warning(
            "rejected scope token (scope=%s) at the nginx auth_request target",
            payload.get("scope"),
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="jeton hors scope")
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
