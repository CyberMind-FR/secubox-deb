# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit dpkg backing resolver
"""

import subprocess
from functools import lru_cache


def resolve_pkg(path: str, runner=subprocess.run) -> str | None:
    """Return the dpkg package owning `path`, or None if not dpkg-backed."""
    try:
        r = runner(["dpkg", "-S", path], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    # "pkg: /path"  (diversions -> "pkg, other: /path"; take first pkg token)
    head = r.stdout.splitlines()[0].split(":", 1)[0]
    return head.split(",", 1)[0].strip() or None


def is_backed(path: str, runner=subprocess.run) -> bool:
    """Check if a path is owned by a dpkg package."""
    return resolve_pkg(path, runner=runner) is not None


@lru_cache(maxsize=4096)
def is_backed_cached(path: str) -> bool:
    """Cached version of is_backed using default subprocess.run."""
    return is_backed(path)
