"""Single mutation entry point for SecuBox users.

Every API handler and the CLI call into this module. No code outside
`engine.Engine` writes users.json directly.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("secubox.users.engine")

USERNAME_RE = re.compile(r"^[a-z0-9_-]{2,32}$")
ALLOWED_ROLES = {"admin", "operator", "viewer"}


class EngineError(ValueError):
    """Raised for any policy/state violation. Maps to HTTP 4xx in API."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Engine:
    """Atomic, single-file mutation engine."""

    def __init__(self, users_path: Path):
        self.users_path = Path(users_path)
        self._revoke_cb: Optional[Callable[[str], int]] = None
        self._audit_cb: Optional[Callable[[str, str, Dict[str, Any]], None]] = None

    # ── Wiring ────────────────────────────────────────────────────────

    def set_revoke_callback(self, cb: Callable[[str], int]) -> None:
        """Set callback invoked on disable_user. Returns number of sessions revoked."""
        self._revoke_cb = cb

    def set_audit_callback(self, cb: Callable[[str, str, Dict[str, Any]], None]) -> None:
        """Set callback for engine-emitted audit events."""
        self._audit_cb = cb

    def _audit(self, event: str, user: str, details: Optional[Dict[str, Any]] = None) -> None:
        if self._audit_cb:
            try:
                self._audit_cb(event, user, details or {})
            except Exception as exc:
                log.warning("audit callback failed: %s", exc)

    # ── File I/O ──────────────────────────────────────────────────────

    def _load(self) -> Dict[str, Any]:
        if not self.users_path.exists():
            return {"version": 2, "users": [], "groups": []}
        return json.loads(self.users_path.read_text())

    def _save(self, doc: Dict[str, Any]) -> None:
        """Atomic write: temp + os.replace in the same dir."""
        self.users_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".users.json.", dir=str(self.users_path.parent)
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(doc, f, indent=2, sort_keys=True)
            os.replace(tmp_path, self.users_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _find(self, doc: Dict[str, Any], username: str) -> Optional[Dict[str, Any]]:
        for u in doc.get("users", []):
            if u.get("username") == username:
                return u
        return None

    # ── Lifecycle ────────────────────────────────────────────────────

    def list_users(self) -> List[Dict[str, Any]]:
        return list(self._load().get("users", []))

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        return self._find(self._load(), username)

    def create_user(self, username: str, email: Optional[str], role: str) -> Dict[str, Any]:
        if not USERNAME_RE.match(username):
            raise EngineError(f"username invalid: {username!r}")
        if role not in ALLOWED_ROLES:
            raise EngineError(f"role invalid: {role!r}")
        doc = self._load()
        if self._find(doc, username):
            raise EngineError(f"user exists: {username}")
        u = {
            "username": username,
            "email": email,
            "role": role,
            "enabled": True,
            "password_hash": None,
            "must_change_password": True,
            "totp": None,
            "google": None,
            "services": [],
            "created": _now_iso(),
            "last_login": None,
        }
        doc.setdefault("users", []).append(u)
        self._save(doc)
        self._audit("user_created", username, {"role": role})
        return u

    def disable_user(self, username: str) -> int:
        """Disable user, revoke sessions. Returns count of revoked sessions."""
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"user not found: {username}")
        u["enabled"] = False
        self._save(doc)
        revoked = 0
        if self._revoke_cb:
            try:
                revoked = int(self._revoke_cb(username) or 0)
            except Exception as exc:
                log.warning("revoke_cb failed for %s: %s", username, exc)
        self._audit("user_disabled", username, {"revoked": revoked})
        return revoked

    def enable_user(self, username: str) -> None:
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"user not found: {username}")
        u["enabled"] = True
        self._save(doc)
        self._audit("user_enabled", username, {})
