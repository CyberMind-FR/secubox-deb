# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.joinlink — single-use, time-boxed join link. The token
secret travels ONLY in the shared URL; only its BLAKE2b hash is journaled
(same discipline as the session token). Redeem is single-use + expiry-checked
by the caller (escalate.py / ctl).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import token as _token


def _now_plus(ttl_s: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=int(ttl_s))
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def mint_join(ref: str, ttl_s: int, base_url: str) -> dict:
    tok, tok_hash = _token.mint()
    return {"url": f"{base_url.rstrip('/')}/assist/join/{tok}", "token": tok,
            "token_hash": tok_hash, "ref": ref, "expires_at": _now_plus(ttl_s)}


def verify_join(tok: str, token_hash: str) -> bool:
    return _token.verify_token(tok, token_hash)


def is_expired(expires_at: str, now_ts: str) -> bool:
    return str(now_ts) >= str(expires_at)
