# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""HMAC-signed report tokens + (TODO Phase 4) PDF gen. Phase 1 = token mgmt only."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from .models import ReportToken


def mint_token(mac_hash: str, salt: str, ttl_seconds: int = 86400) -> ReportToken:
    """Mint an HMAC-signed ephemeral token for /report/{token} access."""
    expires_at = int(time.time()) + ttl_seconds
    nonce = secrets.token_urlsafe(8)
    raw = f"{mac_hash}:{expires_at}:{nonce}".encode()
    sig = hmac.new(salt.encode(), raw, hashlib.sha256).hexdigest()[:16]
    token = f"{mac_hash}.{expires_at}.{nonce}.{sig}"
    return ReportToken(token=token, mac_hash=mac_hash, expires_at=expires_at)


def verify_token(token: str, salt: str) -> tuple[bool, str | None]:
    """Returns (ok, mac_hash) — ok=False if expired / bad signature / malformed."""
    try:
        mac_hash, exp_str, nonce, sig = token.split(".")
        expires_at = int(exp_str)
    except (ValueError, AttributeError):
        return False, None
    if expires_at < int(time.time()):
        return False, None
    raw = f"{mac_hash}:{expires_at}:{nonce}".encode()
    expected = hmac.new(salt.encode(), raw, hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return False, None
    return True, mac_hash
