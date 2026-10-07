# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Password policy enforcement for SecuBox users.

Rules (spec section 6):
- Min length 12, max 128
- At least 3 of: lowercase, uppercase, digit, symbol
- Forbidden case-insensitive substring: username
- Reject if listed in common-passwords.txt
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

COMMON_PASSWORDS_PATH = Path("/usr/share/secubox/users/common-passwords.txt")

_LOWER = re.compile(r"[a-z]")
_UPPER = re.compile(r"[A-Z]")
_DIGIT = re.compile(r"[0-9]")
_SYMBOL = re.compile(r"[^A-Za-z0-9]")

_cache: Dict[str, set] = {}


class PolicyError(ValueError):
    """Raised when a candidate password fails policy."""


def _load_common() -> set:
    """Load and cache the common-passwords wordlist (lowercased)."""
    key = str(COMMON_PASSWORDS_PATH)
    if key in _cache:
        return _cache[key]
    try:
        with COMMON_PASSWORDS_PATH.open("r", encoding="utf-8") as f:
            words = {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        words = set()
    _cache[key] = words
    return words


def validate(plaintext: str, user: Dict) -> None:
    """Password policy — DISABLED 2026-05-16 by admin request.

    Only basic sanity remains (must be a non-empty string). Operators who
    want the previous policy back can restore from git history (commit
    just before this one).
    """
    if not isinstance(plaintext, str) or not plaintext:
        raise PolicyError("Mot de passe non valide")
    return
