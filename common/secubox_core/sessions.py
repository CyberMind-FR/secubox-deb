# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: SessionStore — shared, read-only view of the live sessions (#942)
CyberMind — https://cybermind.fr

`secubox-auth` owns `sessions.json`: it appends on login and rewrites on
logout / revocation / password change. Every OTHER module needs to *read* it
to answer one question — "is this jti still alive?".

Before #942 they could not: `secubox_core.auth` shipped a permissive default
(`lambda jti: True`) that only `secubox-auth` replaced. On gk2 that left the
44 modules served on their own socket accepting revoked sessions forever,
while the 116 mounted in the aggregator were covered only by the side effect
of `auth` being imported into the same interpreter.

Design constraints:

- **No IPC on the hot path.** One `stat()` per call, a full parse only when
  the file actually changed. An extra network hop per request is what made
  the aggregator a SPOF; we are not repeating it.
- **Fail closed.** Missing, unreadable or corrupt store ⇒ every jti is
  invalid. The recovery path stays open because `secubox-auth` installs its
  own validator and *creates* sessions: logging in still works even when this
  store cannot be read, and a successful login rewrites the file.
- **No write path.** This module never touches the file. Exactly one writer.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional, Set, Tuple

from .logger import get_logger

log = get_logger("sessions")

DEFAULT_PATH = "/var/lib/secubox/auth/sessions.json"

# Escape hatch for the #942 rollout. Set to 1 to restore the pre-#942
# behaviour (every jti accepted) if the strict store locks a fleet out.
# TEMPORARY — to be removed once the batch is validated in production.
# Tracked in #942; do not let this outlive the migration.
PERMISSIVE_ENV = "SECUBOX_AUTH_PERMISSIVE_SESSIONS"

# (path, mtime_ns, size) of the parse currently held in _ids.
_stamp: Optional[Tuple[str, int, int]] = None
_ids: Set[str] = set()


def _path() -> Path:
    """Resolved at call time, not import time, so tests and units can move it."""
    return Path(os.environ.get("SECUBOX_AUTH_SESSIONS", DEFAULT_PATH))


def invalidate_cache() -> None:
    """Drop the cached parse. Used by tests and after a known rewrite."""
    global _stamp, _ids
    _stamp = None
    _ids = set()


def _live_ids() -> Set[str]:
    """Session ids currently in the store. Empty set on any failure."""
    global _stamp, _ids
    p = _path()
    try:
        st = p.stat()
    except OSError:
        # Absent or untraversable ⇒ nothing is valid.
        _stamp = None
        _ids = set()
        return _ids

    stamp = (str(p), st.st_mtime_ns, st.st_size)
    if stamp == _stamp:
        return _ids

    ids: Set[str] = set()
    try:
        rows = json.loads(p.read_text())
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    sid = row.get("id")
                    if isinstance(sid, str) and sid:
                        ids.add(sid)
        else:
            log.warning("sessions store is not a list (%s) — treating as empty", p)
    except (OSError, ValueError) as exc:
        # Corrupt or racing with a rewrite. Deny, and re-read next call: the
        # stamp is recorded either way so a persistently broken file does not
        # get re-parsed on every single request.
        log.warning("sessions store unreadable (%s): %s", p, exc)

    _stamp = stamp
    _ids = ids
    return _ids


def is_valid(jti: Optional[str]) -> bool:
    """True when `jti` names a live session. Fail-closed on every error path."""
    if os.environ.get(PERMISSIVE_ENV) == "1":
        log.warning(
            "%s=1 — session validation DISABLED, every jti accepted. "
            "This is the #942 rollback switch and must not stay on.",
            PERMISSIVE_ENV,
        )
        return True
    if not jti:
        return False
    return jti in _live_ids()


def count() -> int:
    """Number of live sessions — for status endpoints, never for decisions."""
    return len(_live_ids())
