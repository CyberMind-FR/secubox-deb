# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Git-backed revision store — every billet's content + style is versioned in a
Gitea repo, giving full edit history (the metablogizer pattern, per-billet).

Each billet is one Markdown file `billets/<id>.md` with a YAML front-matter
header (slug, status, timestamps, ref/embed URLs, style/theme) followed by the
body. Publish/edit writes the file and `git commit`s it; if an `origin` remote
is configured it also pushes to Gitea. Full history = `git log --follow` on the
file = the billet's revisions.

Best-effort and SIDE-EFFECT-ONLY: the DB write is the source of truth, so a git
or Gitea hiccup never fails a publish. `commit_revision` is synchronous
(subprocess git); callers on the async aggregator loop MUST run it via
`asyncio.to_thread` so it never blocks the shared event loop."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Optional

COMMIT_NAME = "SecuBox Billets"
COMMIT_EMAIL = "billets@secubox.in"
_GIT_TIMEOUT = 15
_PUSH_TIMEOUT = 30


def _git(repo: Path, *args: str, timeout: int = _GIT_TIMEOUT,
         check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo),
         "-c", f"user.name={COMMIT_NAME}", "-c", f"user.email={COMMIT_EMAIL}",
         "-c", f"safe.directory={repo}", *args],
        capture_output=True, text=True, timeout=timeout, check=check,
    )


def ensure_repo(repo_dir: Path) -> None:
    """Create the revision repo if missing (idempotent)."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    if not (repo_dir / ".git").is_dir():
        _git(repo_dir, "init", "-q")
    (repo_dir / "billets").mkdir(parents=True, exist_ok=True)


def _front_matter(meta: dict[str, Any]) -> str:
    lines = ["---"]
    for k in ("slug", "status", "created_at", "updated_at", "published_at",
              "ref_url", "embed_url", "embed_provider", "style"):
        if k in meta and meta[k] is not None:
            lines.append(f"{k}: {json.dumps(meta[k], ensure_ascii=False)}")
    lines.append("---")
    return "\n".join(lines)


def revision_document(body: str, meta: dict[str, Any]) -> str:
    return f"{_front_matter(meta)}\n\n{body.rstrip()}\n"


def commit_revision(repo_dir: Path, billet_id: str, body: str, meta: dict[str, Any],
                    message: str) -> dict:
    """Write billets/<id>.md and commit it; push if an origin remote exists.

    Returns {committed, pushed, commit, reason}; never raises for the ordinary
    'no change' / 'no remote' / 'push rejected' cases."""
    try:
        ensure_repo(repo_dir)
        rel = Path("billets") / f"{billet_id}.md"
        (repo_dir / rel).write_text(revision_document(body, meta), encoding="utf-8")
        _git(repo_dir, "add", str(rel))
        if _git(repo_dir, "diff", "--cached", "--quiet", check=False).returncode == 0:
            return {"committed": False, "pushed": False, "commit": None, "reason": "no-change"}
        _git(repo_dir, "commit", "-q", "-m", message)
        sha = _git(repo_dir, "rev-parse", "HEAD").stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        return {"committed": False, "pushed": False, "commit": None, "reason": f"git-error:{e}"}

    # Push only if an origin remote is configured (Gitea).
    try:
        remotes = _git(repo_dir, "remote", check=False).stdout.split()
        if "origin" not in remotes:
            return {"committed": True, "pushed": False, "commit": sha, "reason": "no-remote"}
        _git(repo_dir, "push", "origin", "HEAD", timeout=_PUSH_TIMEOUT)
        return {"committed": True, "pushed": True, "commit": sha, "reason": "ok"}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        return {"committed": True, "pushed": False, "commit": sha, "reason": f"push-error:{e}"}


def list_revisions(repo_dir: Path, billet_id: str) -> list[dict]:
    """Return the commit history for one billet (newest first)."""
    rel = f"billets/{billet_id}.md"
    try:
        out = _git(repo_dir, "log", "--follow", "--format=%H\x1f%aI\x1f%s", "--", rel,
                   check=False)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return []
    revs = []
    for line in out.stdout.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 3:
            revs.append({"commit": parts[0], "date": parts[1], "message": parts[2]})
    return revs
