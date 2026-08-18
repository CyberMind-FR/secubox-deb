# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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

    #: Etat d'anti-rejeu TOTP. DELIBEREMENT hors du magasin d'utilisateurs
    #: (#990) : `last_step` est de l'etat d'execution, pas de la configuration,
    #: et /etc/secubox appartient a root alors que le service auth tourne en
    #: `secubox`. Ecrire l'anti-rejeu dans le magasin faisait echouer en 500
    #: tout code VALIDE — `_save` n'etant appele que dans la branche de succes,
    #: un mauvais code repondait proprement 401 et un bon code plantait.
    DEFAULT_REPLAY_PATH = Path("/var/lib/secubox/totp-replay.json")

    def __init__(self, users_path: Path, replay_path: Optional[Path] = None):
        self.users_path = Path(users_path)
        # Surcharge par SECUBOX_TOTP_REPLAY_PATH : sans elle, tout Engine
        # construit sans argument explicite ecrit dans un fichier SYSTEME
        # partage. En production c'est voulu ; dans une suite de tests c'est un
        # etat qui fuit d'un test a l'autre et rend les resultats dependants de
        # la machine — constate en ecrivant ce correctif, un test existant
        # s'est mis a echouer parce qu'un run precedent avait laisse une entree.
        env_override = os.environ.get("SECUBOX_TOTP_REPLAY_PATH")
        if replay_path:
            self.replay_path = Path(replay_path)
        elif env_override:
            self.replay_path = Path(env_override)
        else:
            self.replay_path = self.DEFAULT_REPLAY_PATH
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
        """Atomic write: temp + os.replace in the same dir.

        Preserves the existing file's owner + mode. Without this, a root-run CLI
        (``sudo usersctl set-password``) would leave users.json as root:root 0600
        — unreadable by the secubox-owned auth service, which then falls back to
        the auth.toml emergency users and rejects every login. Mirrors
        secubox_core.user_store.set_password's owner-preservation.
        """
        self.users_path.parent.mkdir(parents=True, exist_ok=True)
        prev_stat = None
        try:
            prev_stat = self.users_path.stat()
        except FileNotFoundError:
            pass
        fd, tmp_path = tempfile.mkstemp(
            prefix=".users.json.", dir=str(self.users_path.parent)
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(doc, f, indent=2, sort_keys=True)
            if prev_stat is not None:
                # Re-apply the prior owner/mode so a root writer does not strip
                # the secubox service's access. Fail-open: a non-root writer that
                # cannot chown keeps its own (identical) ownership.
                try:
                    os.chown(tmp_path, prev_stat.st_uid, prev_stat.st_gid)
                except OSError:
                    pass
                try:
                    os.chmod(tmp_path, prev_stat.st_mode & 0o777)
                except OSError:
                    pass
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

    # ── Passwords ────────────────────────────────────────────────────

    def set_password(self, username: str, plaintext: str) -> None:
        """Hash + store password. Validates policy. Clears must_change_password."""
        from argon2 import PasswordHasher
        from . import password_policy

        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"utilisateur inconnu : {username}")
        password_policy.validate(plaintext, u)
        u["password_hash"] = PasswordHasher().hash(plaintext)
        u["must_change_password"] = False
        self._save(doc)
        self._audit("password_set", username, {})

    def clear_password(self, username: str) -> None:
        """Remove password hash and force re-set on next login."""
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"utilisateur inconnu : {username}")
        u["password_hash"] = None
        u["must_change_password"] = True
        self._save(doc)
        self._audit("password_cleared", username, {})

    def verify_password_for_user(self, username: str, plaintext: str) -> bool:
        from argon2 import PasswordHasher
        from argon2.exceptions import InvalidHash, VerifyMismatchError

        u = self._find(self._load(), username)
        if not u or not u.get("enabled") or not u.get("password_hash"):
            return False
        try:
            return PasswordHasher().verify(u["password_hash"], plaintext)
        except (VerifyMismatchError, InvalidHash):
            return False

    # ── TOTP ─────────────────────────────────────────────────────────

    def enroll_totp(self, username: str, secret: str) -> list:
        """Persist secret + freshly generated backup codes. Returns the 10 plaintext codes (shown once)."""
        from . import totp as _totp

        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"user not found: {username}")
        if u.get("totp") and u["totp"].get("enabled"):
            raise EngineError(f"TOTP already enrolled for {username}")
        plain = _totp.generate_backup_codes(n=10, length=10)
        u["totp"] = {
            "secret": secret,
            "enabled": True,
            "enrolled_at": _now_iso(),
            "last_step": None,
            "backup_codes": [
                {"hash": _totp.hash_backup_code(c), "used_at": None} for c in plain
            ],
        }
        self._save(doc)
        self._audit("totp_enrolled", username, {})
        return plain

    # ── Anti-rejeu TOTP (#990) ────────────────────────────────────────
    #
    # Stocke le dernier pas consomme par utilisateur, dans un fichier que le
    # service auth peut ecrire. Best-effort en LECTURE (un fichier absent ou
    # corrompu ne doit pas empecher de se connecter), strict en ECRITURE : si
    # l'etat ne peut pas etre persiste, l'erreur remonte — sans lui, un code
    # redevient rejouable dans sa fenetre, et c'est la seule raison d'etre de
    # ce mecanisme.

    def _replay_load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.replay_path.read_text())
        except (OSError, ValueError):
            return {}

    def _replay_record(self, username: str, step: int) -> None:
        state = self._replay_load()
        state[username] = step
        self.replay_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.replay_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        os.replace(tmp, self.replay_path)

    def verify_totp_for_user(self, username: str, code: str, window: int = 1) -> bool:
        import pyotp
        import time

        doc = self._load()
        u = self._find(doc, username)
        if not u or not u.get("enabled") or not (u.get("totp") and u["totp"].get("enabled")):
            return False

        secret = u["totp"]["secret"]
        # Plancher = le plus RECENT des deux sources. Le last_step herite de
        # users.json doit continuer de compter apres migration, sinon les codes
        # deja consommes redeviendraient acceptables.
        legacy_step = u["totp"].get("last_step")
        replay_step = self._replay_load().get(username)
        candidates = [x for x in (legacy_step, replay_step) if x is not None]
        last_step = max(candidates) if candidates else None
        step_size = 30
        now = int(time.time())
        current = now // step_size

        for delta in range(-window, window + 1):
            step = current + delta
            if pyotp.TOTP(secret).at(step * step_size) == code:
                if last_step is not None and step <= last_step:
                    return False
                # JAMAIS self._save(doc) ici : la verification est un chemin de
                # lecture, et le magasin appartient a root (mutations reservees
                # a `sudo usersctl`, cf. la docstring de _save).
                self._replay_record(username, step)
                self._audit("totp_verified", username, {"step": step, "window": window})
                return True
        return False

    def consume_backup_code(self, username: str, code: str) -> bool:
        from . import totp as _totp

        doc = self._load()
        u = self._find(doc, username)
        if not u or not (u.get("totp") and u["totp"].get("enabled")):
            return False
        for bc in u["totp"]["backup_codes"]:
            if bc["used_at"] is None and _totp.verify_backup_code(bc["hash"], code):
                bc["used_at"] = _now_iso()
                self._save(doc)
                self._audit("backup_code_used", username, {
                    "remaining": sum(1 for x in u["totp"]["backup_codes"] if x["used_at"] is None)
                })
                return True
        return False

    def disable_totp(self, username: str) -> None:
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"user not found: {username}")
        u["totp"] = None
        self._save(doc)
        self._audit("totp_disabled", username, {})

    def regenerate_backup_codes(self, username: str) -> list:
        from . import totp as _totp

        doc = self._load()
        u = self._find(doc, username)
        if not u or not (u.get("totp") and u["totp"].get("enabled")):
            raise EngineError(f"TOTP not enrolled for {username}")
        plain = _totp.generate_backup_codes(n=10, length=10)
        u["totp"]["backup_codes"] = [
            {"hash": _totp.hash_backup_code(c), "used_at": None} for c in plain
        ]
        self._save(doc)
        self._audit("backup_codes_regenerated", username, {})
        return plain

    # ── Sessions / audit helpers ─────────────────────────────────────

    def delete_user(self, username: str) -> None:
        doc = self._load()
        before = len(doc.get("users", []))
        doc["users"] = [u for u in doc.get("users", []) if u.get("username") != username]
        if len(doc["users"]) == before:
            raise EngineError(f"user not found: {username}")
        self._save(doc)
        self._audit("user_deleted", username, {})

    def touch_last_login(self, username: str) -> None:
        doc = self._load()
        u = self._find(doc, username)
        if not u:
            return
        u["last_login"] = _now_iso()
        self._save(doc)

    def revoke_sessions(self, username: str) -> int:
        """Dispatch to the revoke callback. Returns count revoked."""
        if not self._revoke_cb:
            return 0
        try:
            return int(self._revoke_cb(username) or 0)
        except Exception as exc:
            log.warning("revoke_sessions(%s) failed: %s", username, exc)
            return 0
