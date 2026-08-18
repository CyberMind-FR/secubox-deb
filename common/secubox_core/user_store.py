# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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


def list_users() -> list[str]:
    """Return all usernames from the canonical store (empty list on fallback/missing)."""
    doc = _load_users_json()
    if not doc:
        return []
    return [u.get("username") for u in doc.get("users", []) if u.get("username")]


def _atomic_write_users(doc: Dict[str, Any]) -> None:
    """Write users.json atomically, preserving 0600 + owner."""
    import os
    import tempfile
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(USERS_PATH.parent), prefix=".users.", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        try:
            if USERS_PATH.exists():
                st = USERS_PATH.stat()
                os.chmod(tmp, st.st_mode & 0o777)
                os.chown(tmp, st.st_uid, st.st_gid)
            else:
                os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, USERS_PATH)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def set_password(username: str, plaintext: str, *, provision: bool = False,
                 role: str = "user", email: Optional[str] = None) -> Dict[str, Any]:
    """Set a user's password (argon2) in the canonical store and return the user.

    This is the single password *write* path, and therefore the natural
    capture point for downstream provisioning (push the same plaintext into
    Nextcloud/PhotoPrism right after calling this). If the user is absent and
    ``provision`` is True a new enabled user is created.

    Raises KeyError if the user is absent and ``provision`` is False, and
    RuntimeError if the canonical store is missing (fallback can't be written).
    """
    if not username or not plaintext:
        raise ValueError("username and plaintext are required")
    doc = _load_users_json()
    if doc is None:
        raise RuntimeError("users.json missing/corrupt; refusing to write")
    doc.setdefault("users", [])
    hash_ = _HASHER.hash(plaintext)
    for u in doc["users"]:
        if u.get("username") == username:
            u["password_hash"] = hash_
            u["must_change_password"] = False
            if email is not None:
                u["email"] = email
            _atomic_write_users(doc)
            log.info("user_store: password set for %s", username)
            return u
    if not provision:
        raise KeyError(f"unknown user {username!r} (pass provision=True to create)")
    new_user = {
        "username": username,
        "email": email,
        "role": role,
        "enabled": True,
        "password_hash": hash_,
        "must_change_password": False,
        "totp": None,
        "google": None,
    }
    doc["users"].append(new_user)
    _atomic_write_users(doc)
    log.info("user_store: provisioned new user %s (role=%s)", username, role)
    return new_user


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
