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
    """Validate a candidate password against the policy. Raises PolicyError on fail."""
    if not isinstance(plaintext, str):
        raise PolicyError("Mot de passe non valide")
    if len(plaintext) < 12:
        raise PolicyError("Mot de passe trop court (minimum 12 caractères)")
    if len(plaintext) > 128:
        raise PolicyError("Mot de passe trop long (maximum 128 caractères)")

    classes = sum(bool(rx.search(plaintext)) for rx in (_LOWER, _UPPER, _DIGIT, _SYMBOL))
    if classes < 3:
        raise PolicyError(
            "Mot de passe doit contenir au moins 3 types : minuscule, majuscule, chiffre, symbole"
        )

    username = (user.get("username") or "").lower()
    if username and len(username) >= 3 and username in plaintext.lower():
        raise PolicyError("Mot de passe ne doit pas contenir le nom d'utilisateur")

    plaintext_lower = plaintext.lower()
    if plaintext_lower in _load_common():
        raise PolicyError("Mot de passe trop commun")
    # Also reject if any common password is a substring of the candidate
    for common_pwd in _load_common():
        if common_pwd in plaintext_lower:
            raise PolicyError("Mot de passe trop commun")
