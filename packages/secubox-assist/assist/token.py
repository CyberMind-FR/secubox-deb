# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.token — single-use session token (secret never journaled).

Only the BLAKE2b-hex (64) of the token is stored in the signed journal
(AssistSession.token_hash). The token secret is delivered to the center over
the encrypted mesh channel and presented once on the WebSocket handshake.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets


def hash_token(tok: str) -> str:
    """BLAKE2b hex digest (64 chars) of the token."""
    return hashlib.blake2b(tok.encode("utf-8"), digest_size=32).hexdigest()


def mint() -> tuple[str, str]:
    """Return (token, token_hash). token is URL-safe, ~43 chars of entropy."""
    tok = secrets.token_urlsafe(32)
    return tok, hash_token(tok)


def verify_token(tok: str, token_hash: str) -> bool:
    """Constant-time compare of hash_token(tok) against the stored hash."""
    return hmac.compare_digest(hash_token(tok), token_hash)
