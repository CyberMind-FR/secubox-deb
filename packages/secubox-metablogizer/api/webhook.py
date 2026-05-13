# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: metablogizer :: deploy webhook
CyberMind — https://cybermind.fr

HMAC-verified Gitea push webhook. On a metablog-* repo push to the default
branch, pull the site dir, invalidate the load_sites cache, optionally
reload nginx if site.json:domain changed, and log to a ring buffer.
"""
import hmac
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("metablogizer.webhook")

SECRET_PATH = Path("/etc/secubox/metablogizer-webhook.secret")

# Module-level cached secret. Read once at first verify call.
_secret_cache: Optional[bytes] = None


def load_secret(path: Path = SECRET_PATH) -> bytes:
    """Read the shared HMAC secret from disk, cached after first read."""
    global _secret_cache
    if _secret_cache is not None:
        return _secret_cache
    if not path.exists():
        raise FileNotFoundError(f"webhook secret not configured at {path}")
    data = path.read_bytes().strip()
    if not data:
        raise ValueError(f"webhook secret at {path} is empty")
    _secret_cache = data
    return data


def verify_signature(secret: bytes, body: bytes, signature_hex: str) -> bool:
    """Constant-time HMAC-SHA256 verify. Returns False on any mismatch."""
    if not signature_hex:
        return False
    try:
        expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_hex)
    except (TypeError, ValueError):
        return False
