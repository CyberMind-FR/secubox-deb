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
import subprocess
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


GIT_FETCH_TIMEOUT = 60
GIT_OP_TIMEOUT = 10


def git_pull(site_dir: Path, branch: str) -> tuple[str, str]:
    """Pull site_dir to origin/<branch>. Returns (old_sha, new_sha).

    Raises subprocess.TimeoutExpired or CalledProcessError on git failure.
    """
    def _git(*args: str, timeout: int = GIT_OP_TIMEOUT) -> str:
        result = subprocess.run(
            ["git", "-C", str(site_dir), *args],
            capture_output=True, text=True, timeout=timeout, check=True,
        )
        return result.stdout.strip()

    old = _git("rev-parse", "HEAD")
    _git("fetch", "--quiet", "origin", branch, timeout=GIT_FETCH_TIMEOUT)
    _git("reset", "--hard", f"origin/{branch}")
    new = _git("rev-parse", "HEAD")
    return old, new


# ─── Deploy ring buffer ──────────────────────────────────────────
_deploys: list[dict] = []
_DEPLOYS_MAX = 50


def _record_deploy(entry: dict) -> None:
    """Append a deploy record; evict oldest beyond cap."""
    _deploys.append(entry)
    if len(_deploys) > _DEPLOYS_MAX:
        _deploys.pop(0)


def list_deploys() -> dict:
    """Return deploys newest-first."""
    return {"deploys": list(reversed(_deploys)), "count": len(_deploys)}
