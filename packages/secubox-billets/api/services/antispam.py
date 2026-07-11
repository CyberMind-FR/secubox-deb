# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Anti-spam primitives for the public comment form.

Three layers: an invisible honeypot field (bots fill it), a signed
submission-time token enforcing a minimum think-time (and a max age), and a
per-ip_hash rate limit (reused from services.security). Comment emails are
BLAKE2b-hashed at rest — never stored in clear, never displayed."""
from __future__ import annotations

import hashlib

from itsdangerous import BadSignature, Signer

_SALT = "billets.form.v1"


def honeypot_tripped(value: str | None) -> bool:
    return bool(value and value.strip())


def issue_form_token(secret: str, *, now_epoch: int) -> str:
    return Signer(secret, salt=_SALT).sign(str(int(now_epoch))).decode("ascii")


def form_token_ok(secret: str, token: str, *, now_epoch: int,
                  min_delay: int = 3, max_age: int = 3600) -> bool:
    """True when the token is authentic and its age is within [min_delay, max_age]."""
    try:
        issued = int(Signer(secret, salt=_SALT).unsign(token).decode("ascii"))
    except (BadSignature, ValueError, Exception):
        return False
    delay = now_epoch - issued
    return min_delay <= delay <= max_age


def email_hash(email: str | None, secret: str) -> str | None:
    if not email:
        return None
    return hashlib.blake2b(f"{secret}\x1f{email.strip().lower()}".encode("utf-8"),
                           digest_size=16).hexdigest()
