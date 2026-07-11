# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: metablogizer :: deploy webhook
CyberMind — https://cybermind.fr

HMAC-verified Gitea push webhook. On a metablog-* repo push to the default
branch, pull the site dir, invalidate the load_sites cache, optionally
reload nginx if site.json:domain changed, and log to a ring buffer.
"""
import asyncio
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
    # Per-invocation safe.directory: site dirs are owned by root (from sub-B
    # ingest) but the service runs as secubox; without this, git 2.35+
    # refuses with "fatal: detected dubious ownership".
    safe_dir = f"safe.directory={site_dir}"

    def _git(*args: str, timeout: int = GIT_OP_TIMEOUT) -> str:
        result = subprocess.run(
            ["git", "-c", safe_dir, "-C", str(site_dir), *args],
            capture_output=True, text=True, timeout=timeout, check=True,
        )
        return result.stdout.strip()

    old = _git("rev-parse", "HEAD")
    _git("fetch", "--quiet", "origin", branch, timeout=GIT_FETCH_TIMEOUT)
    _git("reset", "--hard", f"origin/{branch}")
    new = _git("rev-parse", "HEAD")
    return old, new


# Commit identity for dashboard-originated versions. The push key itself is
# registered in Gitea (as the repo owner); the author line only labels history.
COMMIT_NAME = "SecuBox MetaBlogizer"
COMMIT_EMAIL = "metablogizer@secubox.in"


def git_commit_push(site_dir: Path, message: str) -> dict:
    """Version a dashboard upload into the site's Gitea repo: stage all, commit,
    and push the current branch to origin.

    Best-effort and side-effect-only — the caller has already written the
    content locally (the primary success). This returns a status dict and never
    raises for the normal "no repo" / "nothing changed" / "push rejected" cases,
    so a Gitea hiccup never fails an upload:
      {"pushed": bool, "committed": bool, "commit": <sha|None>, "reason": <str>}
    """
    if not (site_dir / ".git").is_dir():
        return {"pushed": False, "committed": False, "commit": None, "reason": "no-git-repo"}

    safe_dir = f"safe.directory={site_dir}"

    def _git(*args: str, timeout: int = GIT_OP_TIMEOUT, check: bool = True):
        return subprocess.run(
            ["git", "-c", safe_dir, "-c", f"user.name={COMMIT_NAME}",
             "-c", f"user.email={COMMIT_EMAIL}", "-C", str(site_dir), *args],
            capture_output=True, text=True, timeout=timeout, check=check,
        )

    try:
        _git("add", "-A")
        # Nothing staged → no new version to cut.
        if _git("diff", "--cached", "--quiet", check=False).returncode == 0:
            return {"pushed": False, "committed": False, "commit": None, "reason": "no-changes"}
        _git("commit", "-m", message)
        sha = _git("rev-parse", "HEAD").stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.error("gitea version commit failed site=%s: %s", site_dir.name, e)
        return {"pushed": False, "committed": False, "commit": None, "reason": "commit-failed"}

    try:
        _git("push", "origin", "HEAD", timeout=GIT_FETCH_TIMEOUT)
        return {"pushed": True, "committed": True, "commit": sha, "reason": "ok"}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        # Commit is preserved locally; a later deploy/reconcile can push it.
        logger.warning("gitea version push rejected site=%s (commit %s kept local): %s",
                       site_dir.name, sha[:8], e)
        return {"pushed": False, "committed": True, "commit": sha, "reason": "push-rejected"}


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


# ─── Payload classifier ──────────────────────────────────────────
METABLOG_PREFIX = "metablog-"


def classify_payload(payload: dict) -> tuple[str, dict]:
    """Decide what to do with a Gitea push payload.

    Returns one of:
      ("accept",     {site, branch})
      ("skip",       {reason: ...})
      ("malformed",  {reason: ...})
    """
    try:
        ref = payload["ref"]
        repo = payload["repository"]
        name = repo["name"]
        default = repo["default_branch"]
    except (KeyError, TypeError):
        return "malformed", {"reason": "missing-fields"}

    if not name.startswith(METABLOG_PREFIX):
        return "skip", {"reason": "non-metablog", "name": name}
    if ref != f"refs/heads/{default}":
        return "skip", {"reason": "non-default-ref", "ref": ref}
    return "accept", {"site": name[len(METABLOG_PREFIX):], "branch": default}


# ─── Per-site asyncio lock pool ──────────────────────────────────
# Two pushes to the same site serialize; pushes to different sites run concurrently.
_site_locks: dict[str, asyncio.Lock] = {}
_locks_master = asyncio.Lock()


async def site_lock(name: str) -> asyncio.Lock:
    """Return (creating if needed) the asyncio.Lock keyed by site name."""
    async with _locks_master:
        if name not in _site_locks:
            _site_locks[name] = asyncio.Lock()
        return _site_locks[name]
