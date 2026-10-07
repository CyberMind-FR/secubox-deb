# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit allowlist loader and matcher
"""

import tomllib
import fnmatch


def load(toml_path: str) -> set[str]:
    """Load allowlist exec_paths from TOML file."""
    try:
        with open(toml_path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return set()
    return set(data.get("allowlist", {}).get("exec_paths", []))


def allowed(path: str, allow: set[str]) -> bool:
    """Check if a path is in the allowlist (supports exact matches and globs)."""
    return any(path == p or fnmatch.fnmatch(path, p) for p in allow)
