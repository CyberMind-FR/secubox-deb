"""Canonical read-only identity reader for SecuBox auth.

Primary source: /etc/secubox/users.json (v2 schema).
Emergency fallback: /etc/secubox/auth.toml [users.*] (plaintext comparison,
logged WARNING + `fallback_active` event on every call).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

USERS_PATH = Path("/etc/secubox/users.json")
AUTH_TOML_PATH = Path("/etc/secubox/auth.toml")

log = logging.getLogger("secubox.user_store")
_HASHER = PasswordHasher()


def _load_users_json() -> Optional[Dict[str, Any]]:
    """Return v2 doc or None if missing/corrupt."""
    try:
        return json.loads(USERS_PATH.read_text())
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("user_store: users.json unreadable (%s)", exc)
        return None


def _load_auth_toml() -> Dict[str, Any]:
    """Return parsed auth.toml, or {} if missing/corrupt."""
    try:
        with AUTH_TOML_PATH.open("rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        log.warning("user_store: auth.toml unreadable (%s)", exc)
        return {}


def get_user(username: str) -> Optional[Dict[str, Any]]:
    """Return the v2 user dict, or a synthesised dict from auth.toml fallback, or None."""
    doc = _load_users_json()
    if doc:
        for u in doc.get("users", []):
            if u.get("username") == username:
                return u
        return None
    # Fallback path
    log.warning("user_store: fallback to auth.toml for get_user(%s)", username)
    toml = _load_auth_toml()
    entry = toml.get("users", {}).get(username)
    if not entry:
        return None
    return {
        "username": username,
        "email": entry.get("email"),
        "role": entry.get("role", "admin"),
        "enabled": True,
        "password_hash": None,           # not used in fallback
        "must_change_password": False,
        "totp": None,
        "google": None,
        "_fallback": True,
        "_fallback_plain_password": entry.get("password"),
    }


def is_enabled(username: str) -> bool:
    u = get_user(username)
    return bool(u and u.get("enabled", False))


def verify_password(username: str, plaintext: str) -> bool:
    """Verify a candidate password. Returns False for unknown user, missing hash, or mismatch."""
    u = get_user(username)
    if not u or not u.get("enabled", False):
        return False
    if u.get("_fallback"):
        expected = u.get("_fallback_plain_password", "")
        return bool(expected) and plaintext == expected
    h = u.get("password_hash")
    if not h:
        return False
    try:
        return _HASHER.verify(h, plaintext)
    except (VerifyMismatchError, InvalidHash):
        return False
    except Exception as exc:
        log.warning("user_store: verify_password error for %s: %s", username, exc)
        return False


def load_with_fallback() -> Dict[str, Any]:
    """Return {'source': 'users.json'|'auth.toml.fallback', 'users': [...]}.

    Useful for the banner/audit emission in higher layers.
    """
    doc = _load_users_json()
    if doc:
        return {"source": "users.json", "users": doc.get("users", [])}
    log.warning("user_store: load_with_fallback active")
    toml = _load_auth_toml()
    users = []
    for name, entry in (toml.get("users", {}) or {}).items():
        users.append({
            "username": name,
            "email": entry.get("email"),
            "role": entry.get("role", "admin"),
            "enabled": True,
            "_fallback": True,
        })
    return {"source": "auth.toml.fallback", "users": users}
