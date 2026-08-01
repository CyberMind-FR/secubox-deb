"""Idempotent v1 → v2 migration for /etc/secubox/users.json.

v1 layout (observed on existing boards):
{
  "admin": { "password_hash": "<sha256>", "email": "...", "role": "admin", "created": "..." },
  "users": [ { "username": "admin", "email": "...", "enabled": true, ... } ]
}

v2 layout (target): see schema/users.json.schema.json.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

log = logging.getLogger("secubox.users.migrate")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _user_template(username: str) -> Dict[str, Any]:
    return {
        "username": username,
        "email": None,
        "role": "admin",
        "enabled": True,
        "password_hash": None,
        "must_change_password": True,
        "totp": None,
        "google": None,
        "services": [],
        "created": _now_iso(),
        "last_login": None,
    }


def _is_v2(doc: Dict[str, Any]) -> bool:
    return doc.get("version") == 2 and isinstance(doc.get("users"), list)


def _snapshot(path: Path) -> Optional[Path]:
    """Timestamped copy taken before any rewrite (#945).

    Nanosecond suffix on purpose: the previous code copied to a FIXED
    `.v1.bak`, so a second migration overwrote the only good copy with the
    already-damaged file. On gk2 that copy was the one thing that made
    recovery possible — it must not be a single slot.
    """
    if not path.exists():
        return None
    dest = path.with_name(f"{path.name}.pre-migrate.{time.time_ns()}")
    try:
        shutil.copy2(path, dest)
        log.info("migrate: snapshot %s", dest)
        return dest
    except OSError as exc:
        log.error("migrate: could NOT snapshot %s (%s) — refusing to migrate", path, exc)
        raise


def migrate(users_path: Path, auth_toml_path: Optional[Path]) -> None:
    """Convert users.json to v2 in place. Idempotent."""
    users_path = Path(users_path)
    doc: Dict[str, Any]
    try:
        doc = json.loads(users_path.read_text())
    except FileNotFoundError:
        doc = {}
    except json.JSONDecodeError as exc:
        log.warning("migrate: users.json corrupt (%s) — starting fresh", exc)
        doc = {}

    # No-op if already v2 AND no pending auth.toml [users.*] to absorb.
    if _is_v2(doc):
        merged = _merge_auth_toml(doc, auth_toml_path)
        if merged is None:
            return
        doc = merged
        _atomic_write(users_path, doc)
        return

    # About to rewrite the credential store — snapshot first, always.
    log.info("migrate: converting %s → v2", users_path)
    _snapshot(users_path)

    legacy_users: Dict[str, Dict[str, Any]] = {}
    array_users: Dict[str, Dict[str, Any]] = {}
    for key, value in (doc or {}).items():
        if key in ("users", "groups", "version"):
            continue
        if isinstance(value, dict):
            legacy_users[key] = value
    for entry in (doc.get("users") or []):
        if isinstance(entry, dict) and entry.get("username"):
            array_users[entry["username"]] = entry

    merged_users: Dict[str, Dict[str, Any]] = {}
    for username in set(legacy_users) | set(array_users):
        u = _user_template(username)
        legacy = legacy_users.get(username, {})
        u["email"] = legacy.get("email", u["email"])
        u["role"] = legacy.get("role", u["role"])
        u["created"] = legacy.get("created", u["created"])
        # Legacy flat blocks carry UNSALTED SHA-256 inherited from auth.toml.
        # Those cannot become argon2id without a re-prompt, so they are
        # dropped and the account is forced through a password reset.
        u["password_hash"] = None
        u["must_change_password"] = True

        # An array entry is ALREADY v2: its fields are authoritative, secrets
        # included. Overlaying it wholesale is what #945 fixes — the previous
        # code copied only email/enabled/services/created from here and then
        # nulled the hash unconditionally, so every already-migrated account
        # lost its argon2 hash and its TOTP the moment the `version` key went
        # missing.
        arr = array_users.get(username, {})
        for field, value in arr.items():
            if field == "username":
                continue
            u[field] = value

        merged_users[username] = u

    v2 = {
        "$schema": "https://secubox.in/schemas/users-v2.json",
        "version": 2,
        "users": sorted(merged_users.values(), key=lambda x: x["username"]),
        "groups": doc.get("groups", []) or [],
    }
    v2 = _merge_auth_toml(v2, auth_toml_path) or v2
    _atomic_write(users_path, v2)


def _merge_auth_toml(doc: Dict[str, Any], auth_toml_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Return doc with any auth.toml users absorbed, or None if no change needed."""
    if not auth_toml_path or not Path(auth_toml_path).exists():
        return None
    try:
        with Path(auth_toml_path).open("rb") as f:
            toml = tomllib.load(f) or {}
    except Exception as exc:
        log.warning("migrate: auth.toml unreadable (%s)", exc)
        return None
    toml_users = toml.get("users", {}) or {}
    if not toml_users:
        return None
    existing = {u["username"] for u in doc.get("users", [])}
    changed = False
    for username, entry in toml_users.items():
        if username in existing:
            continue
        u = _user_template(username)
        u["email"] = entry.get("email", u["email"])
        u["role"] = entry.get("role", u["role"])
        u["password_hash"] = None
        u["must_change_password"] = True
        doc.setdefault("users", []).append(u)
        changed = True
    if not changed:
        return None
    doc["users"] = sorted(doc["users"], key=lambda x: x["username"])
    return doc


def _atomic_write(path: Path, doc: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True))
    os.replace(tmp, path)
