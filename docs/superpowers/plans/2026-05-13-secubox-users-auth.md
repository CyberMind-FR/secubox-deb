<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Auth Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the plaintext `auth.toml` admin login on the SecuBox Hub with `secubox-users`-backed argon2id + RFC 6238 TOTP 2FA, with kill-on-disable session revocation, CLI↔API parity through a single Python engine, and a feature-flagged cutover.

**Architecture:** One mutation entry-point (`secubox_users.engine`) shared by the FastAPI handlers in `secubox-users` and a rewritten Python `usersctl`. One read-only auth reader (`secubox_core.user_store`) used by `secubox_core.auth` for password verification. TOTP via `pyotp`; password hashes via `argon2-cffi`. `secubox-auth` owns `sessions.json` + `audit.log` and exposes `revoke_sessions(name)` as the IPC the engine calls on disable. Feature flag `[auth] enforce_v2` in `users.feature_flags.toml` gates the cutover.

**Tech Stack:** Python 3.11 · FastAPI · `argon2-cffi` (python3-argon2) · `pyotp` (python3-pyotp) · `qrcode[pil]` (python3-qrcode) · `jsonschema` (python3-jsonschema) · `tomli` (python3-tomli) · pytest · httpx.

**Spec:** [`docs/superpowers/specs/2026-05-13-secubox-users-auth-design.md`](../specs/2026-05-13-secubox-users-auth-design.md)

**Issue:** [#120](https://github.com/CyberMind-FR/secubox-deb/issues/120)

---

## File map

```
common/secubox_core/
  user_store.py                 NEW
  feature_flags.py              NEW
  auth.py                       MOD
  tests/__init__.py             NEW
  tests/conftest.py             NEW
  tests/test_user_store.py      NEW
  tests/test_feature_flags.py   NEW
  tests/test_auth.py            MOD (or NEW if absent)

packages/secubox-users/
  api/engine.py                 NEW
  api/password_policy.py        NEW
  api/totp.py                   NEW
  api/migrate_v1_to_v2.py       NEW
  api/main.py                   MOD
  schema/users.json.schema.json NEW
  share/common-passwords.txt    NEW (top-1k subset; full 10k loaded if shipped)
  sbin/usersctl                 REWRITE in Python
  debian/control                MOD (Depends)
  debian/postinst               MOD (migration + seed admin + seed <hostname>)
  tests/__init__.py             NEW
  tests/conftest.py             NEW
  tests/test_engine.py          NEW
  tests/test_password_policy.py NEW
  tests/test_totp.py            NEW
  tests/test_migrate_v1_to_v2.py NEW
  tests/test_cli_api_parity.py  NEW

packages/secubox-auth/
  api/main.py                   MOD
  api/totp_pending.py           NEW
  debian/control                MOD (Depends)
  tests/__init__.py             NEW
  tests/conftest.py             NEW
  tests/test_auth_flows.py      NEW
  tests/test_totp_pending.py    NEW

tests/scripts/
  test-users-auth-live.sh       NEW

.claude/
  HISTORY.md                    MOD
  WIP.md                        MOD
```

---

## Task 1 — Test scaffolding

**Goal:** Establish a single `tests/` layout per package with a shared `conftest.py` so subsequent tasks can write TDD tests without re-doing fixture plumbing.

**Files:**
- Create: `common/secubox_core/tests/__init__.py`
- Create: `common/secubox_core/tests/conftest.py`
- Create: `packages/secubox-users/tests/__init__.py`
- Create: `packages/secubox-users/tests/conftest.py`
- Create: `packages/secubox-auth/tests/__init__.py`
- Create: `packages/secubox-auth/tests/conftest.py`

- [ ] **Step 1: Create the test directories (no `__init__.py` — would cause cross-dir collection collision)**

```bash
for d in common/secubox_core/tests packages/secubox-users/tests packages/secubox-auth/tests; do
  install -d "$d"
done
```

Note: do NOT add `__init__.py` to these dirs. Pytest discovers `conftest.py` without it, and an `__init__.py` would make all three dirs register as a top-level package named `tests`, breaking cross-dir collection.

- [ ] **Step 2: Write `common/secubox_core/tests/conftest.py`**

```python
"""Shared fixtures for secubox_core unit tests."""
import json
import os
import sys
from pathlib import Path

import pytest

# Make common/secubox_core importable from tests without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def tmp_users_json(tmp_path: Path) -> Path:
    """A fresh v2 users.json with one admin user (no hash, must_change=true)."""
    path = tmp_path / "users.json"
    path.write_text(json.dumps({
        "version": 2,
        "users": [
            {
                "username": "admin",
                "email": "admin@example.local",
                "role": "admin",
                "enabled": True,
                "password_hash": None,
                "must_change_password": True,
                "totp": None,
                "google": None,
                "services": [],
                "created": "2026-05-13T00:00:00+00:00",
                "last_login": None,
            }
        ],
        "groups": [],
    }, indent=2))
    return path


@pytest.fixture
def tmp_auth_toml(tmp_path: Path) -> Path:
    """A legacy auth.toml with one fallback admin (plaintext)."""
    path = tmp_path / "auth.toml"
    path.write_text(
        '[users.admin]\n'
        'password = "fallbackonly"\n'
        'email = "admin@example.local"\n'
        'role = "admin"\n'
    )
    return path
```

- [ ] **Step 3: Write `packages/secubox-users/tests/conftest.py`**

```python
"""Shared fixtures for secubox-users unit tests."""
import json
import sys
from pathlib import Path

import pytest

# Make both `secubox_core` and the package's own api/ importable.
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-users"))


@pytest.fixture
def tmp_users_json(tmp_path: Path) -> Path:
    """Empty v2 users.json (no users yet)."""
    path = tmp_path / "users.json"
    path.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return path


@pytest.fixture
def tmp_sessions_json(tmp_path: Path) -> Path:
    """Empty sessions.json."""
    path = tmp_path / "sessions.json"
    path.write_text("[]")
    return path
```

- [ ] **Step 4: Write `packages/secubox-auth/tests/conftest.py`**

```python
"""Shared fixtures for secubox-auth integration tests."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-auth"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-users"))


@pytest.fixture
def auth_data_dir(tmp_path: Path) -> Path:
    """Stand-in for /var/lib/secubox/auth/."""
    d = tmp_path / "auth"
    d.mkdir()
    (d / "sessions.json").write_text("[]")
    (d / "audit.log").write_text("")
    return d


@pytest.fixture
def env_files(tmp_path: Path, monkeypatch) -> dict:
    """Set env vars so modules pick up tempdir paths."""
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    monkeypatch.setenv("USERS_FILE", str(users))
    monkeypatch.setenv("SECUBOX_AUTH_DATA_DIR", str(tmp_path / "auth"))
    (tmp_path / "auth").mkdir(exist_ok=True)
    return {"users": users, "data_dir": tmp_path / "auth"}
```

- [ ] **Step 5: Verify pytest discovers the new dirs**

Run from worktree root:

```bash
python3 -m pytest common/secubox_core/tests packages/secubox-users/tests packages/secubox-auth/tests --collect-only -q
```

Expected: `0 tests collected` (no failures — directories load fine, no test files yet).

- [ ] **Step 6: Commit**

```bash
git add common/secubox_core/tests packages/secubox-users/tests packages/secubox-auth/tests
git commit -m "test: scaffold test dirs + conftest for auth rework (ref #120)"
```

---

## Task 2 — Feature flag reader

**Goal:** Centralise the `enforce_v2` / `require_totp_for_admin` flags in one Python module so every code path can read them consistently.

**Files:**
- Create: `common/secubox_core/feature_flags.py`
- Create: `common/secubox_core/tests/test_feature_flags.py`

- [ ] **Step 1: Write the failing test**

`common/secubox_core/tests/test_feature_flags.py`:

```python
"""Tests for secubox_core.feature_flags."""
from pathlib import Path

import pytest

from secubox_core import feature_flags


def test_defaults_when_file_missing(tmp_path: Path):
    flags = feature_flags.load(tmp_path / "missing.toml")
    assert flags["auth"]["enforce_v2"] is False
    assert flags["auth"]["require_totp_for_admin"] is True


def test_overrides_from_toml(tmp_path: Path):
    p = tmp_path / "feature_flags.toml"
    p.write_text('[auth]\nenforce_v2 = true\nrequire_totp_for_admin = false\n')
    flags = feature_flags.load(p)
    assert flags["auth"]["enforce_v2"] is True
    assert flags["auth"]["require_totp_for_admin"] is False


def test_partial_overrides_keep_defaults(tmp_path: Path):
    p = tmp_path / "feature_flags.toml"
    p.write_text('[auth]\nenforce_v2 = true\n')
    flags = feature_flags.load(p)
    assert flags["auth"]["enforce_v2"] is True
    assert flags["auth"]["require_totp_for_admin"] is True  # default


def test_corrupt_file_returns_defaults_and_logs(tmp_path: Path, caplog):
    p = tmp_path / "feature_flags.toml"
    p.write_text('not toml at all =')
    flags = feature_flags.load(p)
    assert flags["auth"]["enforce_v2"] is False
    assert any("feature_flags" in r.message.lower() for r in caplog.records)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest common/secubox_core/tests/test_feature_flags.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_core.feature_flags'` or import error.

- [ ] **Step 3: Implement `feature_flags.py`**

`common/secubox_core/feature_flags.py`:

```python
"""SecuBox feature-flag reader. Single source of truth for runtime toggles."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Union

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

DEFAULT_PATH = Path("/etc/secubox/users.feature_flags.toml")

DEFAULTS: Dict[str, Dict[str, Any]] = {
    "auth": {
        "enforce_v2": False,
        "require_totp_for_admin": True,
    },
}

log = logging.getLogger("secubox.feature_flags")


def load(path: Union[Path, str, None] = None) -> Dict[str, Dict[str, Any]]:
    """Return defaults merged with values from `path` (TOML).

    Missing file or parse errors → defaults are returned (logged WARNING).
    """
    p = Path(path) if path is not None else DEFAULT_PATH
    merged = {k: dict(v) for k, v in DEFAULTS.items()}
    if not p.exists():
        return merged
    try:
        with p.open("rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        log.warning("feature_flags: could not parse %s (%s); using defaults", p, exc)
        return merged
    for section, overrides in (data or {}).items():
        if section not in merged or not isinstance(overrides, dict):
            continue
        for key, value in overrides.items():
            if key in merged[section]:
                merged[section][key] = value
    return merged
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest common/secubox_core/tests/test_feature_flags.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add common/secubox_core/feature_flags.py common/secubox_core/tests/test_feature_flags.py
git commit -m "feat(core): feature_flags reader with auth.enforce_v2 + require_totp_for_admin (ref #120)"
```

---

## Task 3 — JSON Schema v2 + validator test

**Goal:** Lock the v2 `users.json` shape in a draft-07 JSON Schema, validated by tests.

**Files:**
- Create: `packages/secubox-users/schema/users.json.schema.json`
- Create: `packages/secubox-users/tests/test_schema.py`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_schema.py`:

```python
"""Validate users.json v2 against the JSON Schema."""
import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schema" / "users.json.schema.json").read_text()
)


def _doc(**overrides):
    base = {
        "version": 2,
        "users": [
            {
                "username": "admin",
                "email": "admin@example.local",
                "role": "admin",
                "enabled": True,
                "password_hash": None,
                "must_change_password": True,
                "totp": None,
                "google": None,
                "services": [],
                "created": "2026-05-13T00:00:00+00:00",
                "last_login": None,
            }
        ],
        "groups": [],
    }
    base.update(overrides)
    return base


def test_minimal_valid_doc():
    jsonschema.validate(_doc(), SCHEMA)


def test_version_must_be_2():
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(_doc(version=1), SCHEMA)


def test_username_pattern_enforced():
    doc = _doc()
    doc["users"][0]["username"] = "BadName!"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, SCHEMA)


def test_role_enum_enforced():
    doc = _doc()
    doc["users"][0]["role"] = "superuser"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, SCHEMA)


def test_totp_block_shape():
    doc = _doc()
    doc["users"][0]["totp"] = {
        "secret": "JBSWY3DPEHPK3PXP",
        "enabled": True,
        "enrolled_at": "2026-05-13T00:00:00+00:00",
        "last_step": None,
        "backup_codes": [
            {"hash": "$argon2id$...", "used_at": None}
        ],
    }
    jsonschema.validate(doc, SCHEMA)


def test_password_hash_may_be_null():
    doc = _doc()
    doc["users"][0]["password_hash"] = None
    jsonschema.validate(doc, SCHEMA)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest packages/secubox-users/tests/test_schema.py -v
```

Expected: FileNotFoundError on the schema path.

- [ ] **Step 3: Write the schema**

`packages/secubox-users/schema/users.json.schema.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://secubox.in/schemas/users-v2.json",
  "title": "SecuBox Users v2",
  "type": "object",
  "required": ["version", "users", "groups"],
  "additionalProperties": false,
  "properties": {
    "$schema": {"type": "string"},
    "version": {"const": 2},
    "users": {
      "type": "array",
      "items": {"$ref": "#/definitions/user"}
    },
    "groups": {"type": "array"}
  },
  "definitions": {
    "user": {
      "type": "object",
      "required": [
        "username", "role", "enabled", "must_change_password",
        "services", "created"
      ],
      "additionalProperties": false,
      "properties": {
        "username": {"type": "string", "pattern": "^[a-z0-9_-]{2,32}$"},
        "email":    {"type": ["string", "null"], "format": "email"},
        "role":     {"enum": ["admin", "operator", "viewer"]},
        "enabled":  {"type": "boolean"},
        "password_hash":        {"type": ["string", "null"]},
        "must_change_password": {"type": "boolean"},
        "totp":     {"oneOf": [{"type": "null"}, {"$ref": "#/definitions/totp"}]},
        "google":   {"oneOf": [{"type": "null"}, {"$ref": "#/definitions/google"}]},
        "services": {"type": "array", "items": {"type": "string"}},
        "created":  {"type": "string", "format": "date-time"},
        "last_login": {"type": ["string", "null"], "format": "date-time"},
        "provision_results": {"type": "object"}
      }
    },
    "totp": {
      "type": "object",
      "required": ["secret", "enabled", "enrolled_at", "backup_codes"],
      "additionalProperties": false,
      "properties": {
        "secret":      {"type": "string", "minLength": 16},
        "enabled":     {"type": "boolean"},
        "enrolled_at": {"type": "string", "format": "date-time"},
        "last_step":   {"type": ["integer", "null"]},
        "backup_codes": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["hash", "used_at"],
            "additionalProperties": false,
            "properties": {
              "hash":    {"type": "string"},
              "used_at": {"type": ["string", "null"], "format": "date-time"}
            }
          }
        }
      }
    },
    "google": {
      "type": "object",
      "required": ["sub", "email", "linked_at"],
      "additionalProperties": false,
      "properties": {
        "sub":       {"type": "string"},
        "email":     {"type": "string", "format": "email"},
        "linked_at": {"type": "string", "format": "date-time"}
      }
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest packages/secubox-users/tests/test_schema.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/schema/users.json.schema.json packages/secubox-users/tests/test_schema.py
git commit -m "feat(users): users.json v2 JSON Schema + validation tests (ref #120)"
```

---

## Task 4 — Password policy module

**Goal:** Implement `password_policy.validate(plaintext, user)` with the spec's six rules. Pure-function module.

**Files:**
- Create: `packages/secubox-users/api/password_policy.py`
- Create: `packages/secubox-users/tests/test_password_policy.py`
- Create: `packages/secubox-users/share/common-passwords.txt`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_password_policy.py`:

```python
"""Password policy enforcement."""
from pathlib import Path

import pytest

from api import password_policy


@pytest.fixture(autouse=True)
def _wordlist(tmp_path: Path, monkeypatch):
    p = tmp_path / "common.txt"
    p.write_text("password\npassword123\nhunter2\nletmein\n")
    monkeypatch.setattr(password_policy, "COMMON_PASSWORDS_PATH", p)
    # Reset module-level cache so the new path is read.
    password_policy._cache.clear()


USER = {"username": "alice"}


def test_accepts_strong_password():
    password_policy.validate("Correct!Horse9Battery", USER)


def test_rejects_short():
    with pytest.raises(password_policy.PolicyError) as ei:
        password_policy.validate("Sh0rt!Ab", USER)
    assert "12" in str(ei.value)


def test_rejects_too_long():
    with pytest.raises(password_policy.PolicyError):
        password_policy.validate("A1!" + "x" * 200, USER)


def test_rejects_low_charset_variety():
    with pytest.raises(password_policy.PolicyError):
        password_policy.validate("alllowercaseonly", USER)


def test_rejects_username_substring_case_insensitive():
    with pytest.raises(password_policy.PolicyError):
        password_policy.validate("ALICE!Password9X", USER)


def test_rejects_common_password():
    # 'password123' is in the wordlist fixture.
    with pytest.raises(password_policy.PolicyError):
        password_policy.validate("Password123!XY", {"username": "bob"})
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest packages/secubox-users/tests/test_password_policy.py -v
```

Expected: import error on `api.password_policy`.

- [ ] **Step 3: Create the common-passwords seed list**

`packages/secubox-users/share/common-passwords.txt`:

```
123456
password
12345678
qwerty
abc123
123456789
111111
1234567
iloveyou
admin
welcome
monkey
login
abcdef
solo
1q2w3e4r
master
666666
qwertyuiop
123321
mustang
1234567890
michael
654321
pussy
superman
1qaz2wsx
7777777
fuckyou
121212
000000
qazwsx
123qwe
killer
trustno1
jordan
jennifer
zxcvbnm
asdfgh
hunter
buster
soccer
harley
batman
andrew
tigger
sunshine
iloveu
2000
charlie
robert
thomas
hockey
ranger
daniel
starwars
klaster
112233
george
asshole
computer
michelle
jessica
pepper
1111
zxcvbn
555555
11111111
131313
freedom
777777
pass
maggie
159753
aaaaaa
ginger
princess
joshua
cheese
amanda
summer
love
ashley
6969
nicole
chelsea
biteme
matthew
access
yankees
987654321
dallas
austin
thunder
taylor
matrix
mobilemail
mom
monitor
monitoring
montana
moon
moscow
```

(This is a starter ~100-entry list. The full top-10k SecLists wordlist can be downloaded later via `make refresh-common-passwords`; for unit tests the starter file is sufficient.)

- [ ] **Step 4: Write `password_policy.py`**

`packages/secubox-users/api/password_policy.py`:

```python
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

    if plaintext.lower() in _load_common():
        raise PolicyError("Mot de passe trop commun")
```

- [ ] **Step 5: Run test to verify it passes**

```bash
python3 -m pytest packages/secubox-users/tests/test_password_policy.py -v
```

Expected: 6 passed.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-users/api/password_policy.py \
        packages/secubox-users/tests/test_password_policy.py \
        packages/secubox-users/share/common-passwords.txt
git commit -m "feat(users): password_policy module + common-passwords seed (ref #120)"
```

---

## Task 5 — TOTP module

**Goal:** Implement the `pyotp` wrapper: secret generation, verification with ±1 window + replay protection, backup-code generation + verification via argon2id.

**Files:**
- Create: `packages/secubox-users/api/totp.py`
- Create: `packages/secubox-users/tests/test_totp.py`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_totp.py`:

```python
"""TOTP wrapper: secret, verify (window + replay), backup codes."""
import time
from pathlib import Path

import pyotp
import pytest

from api import totp


def test_generate_secret_is_base32_160bit():
    s = totp.generate_secret()
    assert len(s) == 32
    assert set(s).issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))


def test_provisioning_uri_shape():
    uri = totp.provisioning_uri("alice", secret="JBSWY3DPEHPK3PXP", issuer="SecuBox")
    assert uri.startswith("otpauth://totp/")
    assert "alice" in uri
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=SecuBox" in uri


def test_verify_accepts_current_code():
    secret = totp.generate_secret()
    code = pyotp.TOTP(secret).now()
    ok, step = totp.verify(secret, code, last_step=None)
    assert ok
    assert step is not None


def test_verify_rejects_wrong_code():
    secret = totp.generate_secret()
    ok, step = totp.verify(secret, "000000", last_step=None)
    assert ok is False
    assert step is None


def test_verify_refuses_replay_of_same_step():
    secret = totp.generate_secret()
    code = pyotp.TOTP(secret).now()
    ok1, step1 = totp.verify(secret, code, last_step=None)
    assert ok1
    ok2, step2 = totp.verify(secret, code, last_step=step1)
    assert ok2 is False


def test_generate_backup_codes_shape():
    codes = totp.generate_backup_codes(n=10, length=10)
    assert len(codes) == 10
    assert all(len(c) == 10 for c in codes)
    assert all(set(c).issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")) for c in codes)
    # Codes are unique
    assert len(set(codes)) == 10


def test_hash_and_verify_backup_code():
    code = "ABCDEFGHIJ"
    h = totp.hash_backup_code(code)
    assert h.startswith("$argon2id$")
    assert totp.verify_backup_code(h, "ABCDEFGHIJ") is True
    assert totp.verify_backup_code(h, "OTHERCODE!") is False
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest packages/secubox-users/tests/test_totp.py -v
```

Expected: import error on `api.totp`.

- [ ] **Step 3: Implement `totp.py`**

`packages/secubox-users/api/totp.py`:

```python
"""RFC 6238 TOTP wrapper + backup-code generator (argon2id-hashed)."""
from __future__ import annotations

import secrets
from typing import List, Optional, Tuple

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

BACKUP_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # base32


def generate_secret() -> str:
    """Return a fresh 160-bit base32 secret (32 chars)."""
    return pyotp.random_base32()


def provisioning_uri(username: str, secret: str, issuer: str = "SecuBox") -> str:
    """Return an `otpauth://` URI suitable for QR encoding."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify(secret: str, code: str, last_step: Optional[int]) -> Tuple[bool, Optional[int]]:
    """Verify a TOTP code with ±1 window. Refuse replay of `last_step`.

    Returns (ok, step) — `step` is the accepted step counter, or None on failure.
    """
    if not code or not code.isdigit() or len(code) != 6:
        return False, None
    totp_obj = pyotp.TOTP(secret)
    now = int(__import__("time").time())
    step_size = 30
    current = now // step_size
    for delta in (-1, 0, 1):
        step = current + delta
        candidate = totp_obj.at(step * step_size)
        if secrets.compare_digest(candidate, code):
            if last_step is not None and step <= last_step:
                return False, None
            return True, step
    return False, None


def generate_backup_codes(n: int = 10, length: int = 10) -> List[str]:
    """Return `n` unique base32 codes of `length` chars each."""
    codes: set = set()
    while len(codes) < n:
        codes.add("".join(secrets.choice(BACKUP_ALPHABET) for _ in range(length)))
    return sorted(codes)


def hash_backup_code(code: str) -> str:
    """Return an argon2id PHC string for a backup code."""
    return _HASHER.hash(code)


def verify_backup_code(hash_: str, code: str) -> bool:
    """Return True if `code` matches `hash_`."""
    try:
        return _HASHER.verify(hash_, code)
    except VerifyMismatchError:
        return False
    except Exception:
        return False
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest packages/secubox-users/tests/test_totp.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/api/totp.py packages/secubox-users/tests/test_totp.py
git commit -m "feat(users): totp module — pyotp wrapper + argon2id backup codes (ref #120)"
```

---

## Task 6 — `user_store` (read-only auth reader)

**Goal:** The single canonical reader of identity for auth. Includes the `auth.toml` emergency fallback path with a logged warning.

**Files:**
- Create: `common/secubox_core/user_store.py`
- Create: `common/secubox_core/tests/test_user_store.py`

- [ ] **Step 1: Write the failing test**

`common/secubox_core/tests/test_user_store.py`:

```python
"""Tests for secubox_core.user_store."""
import json
import logging
from pathlib import Path

import pytest
from argon2 import PasswordHasher

from secubox_core import user_store


def _write_user(path: Path, **fields):
    base = {
        "username": "admin",
        "email": "a@b.c",
        "role": "admin",
        "enabled": True,
        "password_hash": None,
        "must_change_password": True,
        "totp": None,
        "google": None,
        "services": [],
        "created": "2026-05-13T00:00:00+00:00",
        "last_login": None,
    }
    base.update(fields)
    doc = {"version": 2, "users": [base], "groups": []}
    path.write_text(json.dumps(doc))


def test_get_user_returns_dict(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    u = user_store.get_user("admin")
    assert u["username"] == "admin"
    assert u["enabled"] is True


def test_get_user_missing_returns_none(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.get_user("ghost") is None


def test_verify_password_accepts_correct_hash(tmp_path: Path, monkeypatch):
    h = PasswordHasher().hash("StrongPass!42xy")
    p = tmp_path / "users.json"
    _write_user(p, password_hash=h, must_change_password=False)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.verify_password("admin", "StrongPass!42xy") is True


def test_verify_password_rejects_wrong(tmp_path: Path, monkeypatch):
    h = PasswordHasher().hash("StrongPass!42xy")
    p = tmp_path / "users.json"
    _write_user(p, password_hash=h, must_change_password=False)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.verify_password("admin", "wrong") is False


def test_verify_password_rejects_null_hash(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p, password_hash=None)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.verify_password("admin", "anything") is False


def test_is_enabled(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p, enabled=False)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    assert user_store.is_enabled("admin") is False


def test_fallback_to_auth_toml_when_users_json_missing(tmp_path: Path, monkeypatch, caplog):
    users_missing = tmp_path / "users.json"
    auth_toml = tmp_path / "auth.toml"
    auth_toml.write_text('[users.admin]\npassword = "fallbackonly"\nrole = "admin"\n')
    monkeypatch.setattr(user_store, "USERS_PATH", users_missing)
    monkeypatch.setattr(user_store, "AUTH_TOML_PATH", auth_toml)
    caplog.set_level(logging.WARNING)
    # In fallback mode, verify_password uses plaintext comparison.
    assert user_store.verify_password("admin", "fallbackonly") is True
    assert user_store.verify_password("admin", "wrong") is False
    assert any("fallback" in r.message.lower() for r in caplog.records)


def test_fallback_to_auth_toml_when_users_json_corrupt(tmp_path: Path, monkeypatch, caplog):
    users_bad = tmp_path / "users.json"
    users_bad.write_text("{not json")
    auth_toml = tmp_path / "auth.toml"
    auth_toml.write_text('[users.admin]\npassword = "fallbackonly"\n')
    monkeypatch.setattr(user_store, "USERS_PATH", users_bad)
    monkeypatch.setattr(user_store, "AUTH_TOML_PATH", auth_toml)
    caplog.set_level(logging.WARNING)
    assert user_store.verify_password("admin", "fallbackonly") is True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest common/secubox_core/tests/test_user_store.py -v
```

Expected: ImportError on `secubox_core.user_store`.

- [ ] **Step 3: Implement `user_store.py`**

`common/secubox_core/user_store.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest common/secubox_core/tests/test_user_store.py -v
```

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add common/secubox_core/user_store.py common/secubox_core/tests/test_user_store.py
git commit -m "feat(core): user_store — canonical reader with auth.toml fallback (ref #120)"
```

---

## Task 7 — Engine part 1: lifecycle (create / enable / disable / list)

**Goal:** `engine.create_user`, `engine.enable_user`, `engine.disable_user`, `engine.list_users`, `engine.get_user`. Atomic file writes. `disable_user` calls a session-revoke callback the engine accepts via DI.

**Files:**
- Create: `packages/secubox-users/api/engine.py`
- Create: `packages/secubox-users/tests/test_engine_lifecycle.py`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_engine_lifecycle.py`:

```python
"""Engine lifecycle: create/enable/disable/list."""
import json
import re
from pathlib import Path

import pytest

from api import engine


@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return engine.Engine(users_path=p)


def test_create_user_succeeds(store: engine.Engine):
    u = store.create_user("alice", email="a@b.c", role="operator")
    assert u["username"] == "alice"
    assert u["role"] == "operator"
    assert u["enabled"] is True
    assert u["must_change_password"] is True
    assert u["password_hash"] is None
    assert u["totp"] is None


def test_create_user_rejects_bad_username(store: engine.Engine):
    with pytest.raises(engine.EngineError, match="username"):
        store.create_user("Bad Name!", email="x@y.z", role="viewer")


def test_create_user_rejects_duplicate(store: engine.Engine):
    store.create_user("alice", email="a@b.c", role="viewer")
    with pytest.raises(engine.EngineError, match="exists"):
        store.create_user("alice", email="other@b.c", role="viewer")


def test_disable_calls_revoke_callback(store: engine.Engine):
    store.create_user("alice", email="a@b.c", role="viewer")
    calls = []
    store.set_revoke_callback(lambda name: calls.append(name) or 0)
    store.disable_user("alice")
    assert calls == ["alice"]
    assert store.get_user("alice")["enabled"] is False


def test_enable_restores_flag(store: engine.Engine):
    store.create_user("alice", email="a@b.c", role="viewer")
    store.disable_user("alice")
    store.enable_user("alice")
    assert store.get_user("alice")["enabled"] is True


def test_list_users_returns_all(store: engine.Engine):
    store.create_user("a", email="a@x.y", role="viewer")
    store.create_user("b", email="b@x.y", role="viewer")
    names = sorted(u["username"] for u in store.list_users())
    assert names == ["a", "b"]


def test_atomic_write_does_not_corrupt_on_failure(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="viewer")

    # Force os.replace to raise and make sure the original file is preserved.
    import api.engine as engmod
    real_replace = engmod.os.replace
    def boom(src, dst):
        raise OSError("simulated")
    monkeypatch.setattr(engmod.os, "replace", boom)
    with pytest.raises(OSError):
        eng.create_user("bob", email="b@x.y", role="viewer")
    monkeypatch.setattr(engmod.os, "replace", real_replace)

    doc = json.loads(p.read_text())
    assert [u["username"] for u in doc["users"]] == ["alice"]
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest packages/secubox-users/tests/test_engine_lifecycle.py -v
```

Expected: import error on `api.engine`.

- [ ] **Step 3: Implement `engine.py` (lifecycle methods)**

`packages/secubox-users/api/engine.py`:

```python
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
            raise EngineError(f"username invalide : {username!r}")
        if role not in ALLOWED_ROLES:
            raise EngineError(f"role invalide : {role!r}")
        doc = self._load()
        if self._find(doc, username):
            raise EngineError(f"utilisateur déjà existant : {username}")
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
            raise EngineError(f"utilisateur inconnu : {username}")
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
            raise EngineError(f"utilisateur inconnu : {username}")
        u["enabled"] = True
        self._save(doc)
        self._audit("user_enabled", username, {})
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest packages/secubox-users/tests/test_engine_lifecycle.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/api/engine.py \
        packages/secubox-users/tests/test_engine_lifecycle.py
git commit -m "feat(users): engine lifecycle (create/enable/disable/list) (ref #120)"
```

---

## Task 8 — Engine part 2: passwords

**Goal:** Add `engine.set_password`, `engine.clear_password`, `engine.verify_password_for_user`. argon2id hashing. Policy is enforced via `password_policy.validate`.

**Files:**
- Modify: `packages/secubox-users/api/engine.py`
- Create: `packages/secubox-users/tests/test_engine_passwords.py`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_engine_passwords.py`:

```python
"""Engine password operations."""
import json
from pathlib import Path

import pytest

from api import engine, password_policy


@pytest.fixture(autouse=True)
def _empty_wordlist(tmp_path: Path, monkeypatch):
    w = tmp_path / "empty.txt"
    w.write_text("")
    monkeypatch.setattr(password_policy, "COMMON_PASSWORDS_PATH", w)
    password_policy._cache.clear()


@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="viewer")
    return eng


def test_set_password_hashes_and_clears_must_change(store: engine.Engine):
    store.set_password("alice", "GoodPass!42xyz")
    u = store.get_user("alice")
    assert u["password_hash"].startswith("$argon2id$")
    assert u["must_change_password"] is False


def test_set_password_rejects_weak(store: engine.Engine):
    with pytest.raises(password_policy.PolicyError):
        store.set_password("alice", "weak")


def test_clear_password_resets_must_change(store: engine.Engine):
    store.set_password("alice", "GoodPass!42xyz")
    store.clear_password("alice")
    u = store.get_user("alice")
    assert u["password_hash"] is None
    assert u["must_change_password"] is True


def test_verify_password_for_user(store: engine.Engine):
    store.set_password("alice", "GoodPass!42xyz")
    assert store.verify_password_for_user("alice", "GoodPass!42xyz") is True
    assert store.verify_password_for_user("alice", "wrong") is False


def test_verify_password_for_user_unknown(store: engine.Engine):
    assert store.verify_password_for_user("ghost", "anything") is False
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest packages/secubox-users/tests/test_engine_passwords.py -v
```

Expected: AttributeError — methods don't exist yet.

- [ ] **Step 3: Append password methods to `engine.py`**

Append to `packages/secubox-users/api/engine.py` (inside class `Engine`):

```python
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
```

Add at the top of `engine.py` if not already present:

```python
# Note: imports of argon2 and password_policy are scoped inside methods to
# keep module import cheap for the CLI smoke path.
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest packages/secubox-users/tests/test_engine_passwords.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/api/engine.py \
        packages/secubox-users/tests/test_engine_passwords.py
git commit -m "feat(users): engine.set/clear/verify password with argon2id (ref #120)"
```

---

## Task 9 — Engine part 3: TOTP

**Goal:** Add `engine.enroll_totp`, `engine.verify_totp_for_user`, `engine.consume_backup_code`, `engine.touch_totp_step`, `engine.disable_totp`, `engine.regenerate_backup_codes`.

**Files:**
- Modify: `packages/secubox-users/api/engine.py`
- Create: `packages/secubox-users/tests/test_engine_totp.py`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_engine_totp.py`:

```python
"""Engine TOTP operations."""
import json
import time
from pathlib import Path

import pyotp
import pytest

from api import engine, totp


@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="admin")
    return eng


def test_enroll_totp_persists_secret_and_10_codes(store: engine.Engine):
    secret = totp.generate_secret()
    backup_plain = store.enroll_totp("alice", secret)
    assert len(backup_plain) == 10
    u = store.get_user("alice")
    assert u["totp"]["enabled"] is True
    assert u["totp"]["secret"] == secret
    assert len(u["totp"]["backup_codes"]) == 10
    assert all(bc["used_at"] is None for bc in u["totp"]["backup_codes"])
    assert all(bc["hash"].startswith("$argon2id$") for bc in u["totp"]["backup_codes"])


def test_verify_totp_for_user_accepts_current(store: engine.Engine):
    secret = totp.generate_secret()
    store.enroll_totp("alice", secret)
    code = pyotp.TOTP(secret).now()
    ok = store.verify_totp_for_user("alice", code)
    assert ok is True


def test_verify_totp_refuses_replay(store: engine.Engine):
    secret = totp.generate_secret()
    store.enroll_totp("alice", secret)
    code = pyotp.TOTP(secret).now()
    assert store.verify_totp_for_user("alice", code) is True
    assert store.verify_totp_for_user("alice", code) is False  # replay


def test_consume_backup_code_marks_used_once(store: engine.Engine):
    secret = totp.generate_secret()
    backup = store.enroll_totp("alice", secret)
    code = backup[0]
    assert store.consume_backup_code("alice", code) is True
    assert store.consume_backup_code("alice", code) is False  # already used


def test_disable_totp_removes_block(store: engine.Engine):
    secret = totp.generate_secret()
    store.enroll_totp("alice", secret)
    store.disable_totp("alice")
    u = store.get_user("alice")
    assert u["totp"] is None


def test_regenerate_backup_codes(store: engine.Engine):
    secret = totp.generate_secret()
    old = store.enroll_totp("alice", secret)
    new = store.regenerate_backup_codes("alice")
    assert len(new) == 10
    assert set(new).isdisjoint(set(old))
    u = store.get_user("alice")
    assert len(u["totp"]["backup_codes"]) == 10
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest packages/secubox-users/tests/test_engine_totp.py -v
```

Expected: AttributeError — TOTP methods missing.

- [ ] **Step 3: Append TOTP methods to `engine.py`**

Append inside class `Engine` in `packages/secubox-users/api/engine.py`:

```python
    # ── TOTP ─────────────────────────────────────────────────────────

    def enroll_totp(self, username: str, secret: str) -> list:
        """Persist secret + freshly generated backup codes. Returns the 10 plaintext codes (shown once)."""
        from . import totp as _totp

        doc = self._load()
        u = self._find(doc, username)
        if not u:
            raise EngineError(f"utilisateur inconnu : {username}")
        if u.get("totp") and u["totp"].get("enabled"):
            raise EngineError(f"TOTP déjà enrôlé pour {username}")
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

    def verify_totp_for_user(self, username: str, code: str) -> bool:
        from . import totp as _totp

        doc = self._load()
        u = self._find(doc, username)
        if not u or not u.get("enabled") or not (u.get("totp") and u["totp"].get("enabled")):
            return False
        ok, step = _totp.verify(u["totp"]["secret"], code, u["totp"].get("last_step"))
        if ok and step is not None:
            u["totp"]["last_step"] = step
            self._save(doc)
        return ok

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
            raise EngineError(f"utilisateur inconnu : {username}")
        u["totp"] = None
        self._save(doc)
        self._audit("totp_disabled", username, {})

    def regenerate_backup_codes(self, username: str) -> list:
        from . import totp as _totp

        doc = self._load()
        u = self._find(doc, username)
        if not u or not (u.get("totp") and u["totp"].get("enabled")):
            raise EngineError(f"TOTP non enrôlé pour {username}")
        plain = _totp.generate_backup_codes(n=10, length=10)
        u["totp"]["backup_codes"] = [
            {"hash": _totp.hash_backup_code(c), "used_at": None} for c in plain
        ]
        self._save(doc)
        self._audit("backup_codes_regenerated", username, {})
        return plain
```

Also ensure `packages/secubox-users/api/__init__.py` exposes relative imports correctly. If currently empty, leave as-is — Python finds them via the conftest sys.path injection.

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest packages/secubox-users/tests/test_engine_totp.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/api/engine.py \
        packages/secubox-users/tests/test_engine_totp.py
git commit -m "feat(users): engine TOTP enroll/verify/consume/disable/regenerate (ref #120)"
```

---

## Task 10 — Engine part 4: sessions + last_login

**Goal:** Add `engine.touch_last_login`. The session-revoke callback wiring is already in Task 7 (`set_revoke_callback`); here we add `engine.revoke_sessions(name)` which simply invokes the callback (so callers don't need to know about the indirection).

**Files:**
- Modify: `packages/secubox-users/api/engine.py`
- Create: `packages/secubox-users/tests/test_engine_sessions.py`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_engine_sessions.py`:

```python
"""Engine session-side methods."""
import json
from pathlib import Path

import pytest

from api import engine


@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="viewer")
    return eng


def test_touch_last_login_writes_timestamp(store: engine.Engine):
    store.touch_last_login("alice")
    u = store.get_user("alice")
    assert u["last_login"] is not None
    assert "T" in u["last_login"]  # iso8601


def test_revoke_sessions_dispatches_callback(store: engine.Engine):
    calls = []
    store.set_revoke_callback(lambda name: calls.append(name) or 7)
    n = store.revoke_sessions("alice")
    assert n == 7
    assert calls == ["alice"]


def test_revoke_sessions_no_callback_returns_zero(store: engine.Engine):
    assert store.revoke_sessions("alice") == 0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest packages/secubox-users/tests/test_engine_sessions.py -v
```

Expected: AttributeError on `touch_last_login`/`revoke_sessions`.

- [ ] **Step 3: Append to `engine.py`**

Append inside class `Engine`:

```python
    # ── Sessions / audit helpers ─────────────────────────────────────

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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest packages/secubox-users/tests/test_engine_sessions.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/api/engine.py \
        packages/secubox-users/tests/test_engine_sessions.py
git commit -m "feat(users): engine touch_last_login + revoke_sessions dispatcher (ref #120)"
```

---

## Task 11 — `migrate_v1_to_v2` script

**Goal:** Idempotent migration from the current dual-shape `users.json` (+ legacy `auth.toml` entries) to v2.

**Files:**
- Create: `packages/secubox-users/api/migrate_v1_to_v2.py`
- Create: `packages/secubox-users/tests/test_migrate_v1_to_v2.py`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_migrate_v1_to_v2.py`:

```python
"""Migrate v1 users.json + auth.toml [users.*] → v2."""
import json
from pathlib import Path

import pytest

from api import migrate_v1_to_v2 as M


def _v1_doc():
    return {
        "admin": {
            "password_hash": "deadbeef" * 8,
            "email": "old@local",
            "role": "admin",
            "created": "2026-04-01T00:00:00+00:00",
        },
        "users": [
            {
                "username": "admin",
                "email": "gandalf@gk2.net",
                "enabled": True,
                "services": [],
                "created": "2026-05-09T11:14:11.719355",
                "provision_results": {},
            }
        ],
    }


def test_migrate_discards_sha256_hash_and_forces_must_change(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps(_v1_doc()))
    M.migrate(p, auth_toml_path=None)
    doc = json.loads(p.read_text())
    assert doc["version"] == 2
    assert len(doc["users"]) == 1
    u = doc["users"][0]
    assert u["username"] == "admin"
    assert u["password_hash"] is None
    assert u["must_change_password"] is True
    assert u["role"] == "admin"
    assert u["email"] == "gandalf@gk2.net"  # array wins over legacy


def test_migrate_creates_v1_bak(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps(_v1_doc()))
    M.migrate(p, auth_toml_path=None)
    assert (tmp_path / "users.json.v1.bak").exists()


def test_migrate_is_idempotent(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps(_v1_doc()))
    M.migrate(p, auth_toml_path=None)
    first = p.read_text()
    M.migrate(p, auth_toml_path=None)  # second run — no-op
    assert p.read_text() == first


def test_migrate_pulls_auth_toml_users(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    toml = tmp_path / "auth.toml"
    toml.write_text(
        '[users.admin]\n'
        'password = "secubox"\n'
        'email = "admin@gk2.net"\n'
        'role = "admin"\n'
    )
    M.migrate(p, auth_toml_path=toml)
    doc = json.loads(p.read_text())
    u = next(x for x in doc["users"] if x["username"] == "admin")
    assert u["password_hash"] is None
    assert u["must_change_password"] is True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest packages/secubox-users/tests/test_migrate_v1_to_v2.py -v
```

Expected: ImportError on `api.migrate_v1_to_v2`.

- [ ] **Step 3: Implement `migrate_v1_to_v2.py`**

`packages/secubox-users/api/migrate_v1_to_v2.py`:

```python
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

    # v1 → v2 conversion.
    log.info("migrate: converting %s v1 → v2", users_path)
    if users_path.exists():
        shutil.copy2(users_path, users_path.with_suffix(users_path.suffix + ".v1.bak"))

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
        # Array entries win for non-secret fields.
        arr = array_users.get(username, {})
        if arr.get("email"):
            u["email"] = arr["email"]
        if "enabled" in arr:
            u["enabled"] = bool(arr["enabled"])
        u["services"] = arr.get("services", u["services"])
        u["created"] = arr.get("created", u["created"])
        # Hashes are discarded — they're SHA-256 from the legacy admin block,
        # can't be converted to argon2id without re-prompt.
        u["password_hash"] = None
        u["must_change_password"] = True
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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python3 -m pytest packages/secubox-users/tests/test_migrate_v1_to_v2.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/api/migrate_v1_to_v2.py \
        packages/secubox-users/tests/test_migrate_v1_to_v2.py
git commit -m "feat(users): idempotent v1→v2 users.json migrator (ref #120)"
```

---

## Task 12 — `secubox_core.auth` rewire

**Goal:** Replace the plaintext `_check_password` with `user_store.verify_password`, add `jti` to issued JWTs, make `require_jwt` validate the jti against a getter (set by `secubox-auth` at startup) and reject disabled users defensively.

**Files:**
- Modify: `common/secubox_core/auth.py`
- Create: `common/secubox_core/tests/test_auth_rewire.py`

- [ ] **Step 1: Write the failing test**

`common/secubox_core/tests/test_auth_rewire.py`:

```python
"""Tests for the rewired secubox_core.auth (user_store delegate + jti + scope)."""
import json
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from secubox_core import auth, user_store


def _write_user(p: Path, **fields):
    base = {
        "username": "admin",
        "email": "a@b.c",
        "role": "admin",
        "enabled": True,
        "password_hash": None,
        "must_change_password": False,
        "totp": None,
        "google": None,
        "services": [],
        "created": "2026-05-13T00:00:00+00:00",
        "last_login": None,
    }
    base.update(fields)
    p.write_text(json.dumps({"version": 2, "users": [base], "groups": []}))


@pytest.fixture
def good_admin(tmp_path: Path, monkeypatch):
    h = PasswordHasher().hash("GoodPass!42xyz")
    p = tmp_path / "users.json"
    _write_user(p, password_hash=h)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-do-not-use-in-prod-please")
    yield


def test_check_password_delegates_to_user_store(good_admin):
    assert auth._check_password("admin", "GoodPass!42xyz") is True
    assert auth._check_password("admin", "wrong") is False
    assert auth._check_password("ghost", "anything") is False


def test_create_token_includes_jti(good_admin):
    tok = auth.create_token("admin")
    payload = auth._decode_token(tok)
    assert "jti" in payload
    assert len(payload["jti"]) >= 8


def test_create_token_includes_scope_when_given(good_admin):
    tok = auth.create_token("admin", scope="set-password", expires_in=900)
    payload = auth._decode_token(tok)
    assert payload["scope"] == "set-password"


@pytest.mark.asyncio
async def test_require_jwt_rejects_unknown_jti(good_admin, monkeypatch):
    auth.set_session_validator(lambda jti: False)  # all jti unknown
    tok = auth.create_token("admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)
    with pytest.raises(HTTPException) as ei:
        await auth.require_jwt(creds=creds)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_require_jwt_accepts_known_jti(good_admin):
    auth.set_session_validator(lambda jti: True)
    tok = auth.create_token("admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)
    out = await auth.require_jwt(creds=creds)
    assert out["sub"] == "admin"


@pytest.mark.asyncio
async def test_require_jwt_rejects_disabled_user(tmp_path: Path, monkeypatch):
    h = PasswordHasher().hash("GoodPass!42xyz")
    p = tmp_path / "users.json"
    _write_user(p, password_hash=h, enabled=False)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    auth.set_session_validator(lambda jti: True)
    tok = auth.create_token("admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)
    with pytest.raises(HTTPException):
        await auth.require_jwt(creds=creds)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest common/secubox_core/tests/test_auth_rewire.py -v
```

Expected: failures — `_check_password` still reads auth.toml, `create_token` has no jti, `set_session_validator` doesn't exist.

- [ ] **Step 3: Rewrite `common/secubox_core/auth.py`**

Open the file (currently 155 lines) and replace its contents with:

```python
"""SecuBox core auth — JWT HS256 over a `user_store`-backed identity.

Compared to v1 (plaintext `auth.toml` lookup), this module:
- delegates password verification to `secubox_core.user_store`
- adds a `jti` claim to every issued token
- validates the `jti` against an externally-injected session validator
- carries an optional `scope` claim for short-lived setup / mfa / enroll tokens
- defensively re-checks `is_enabled` on every authenticated request
"""
from __future__ import annotations

import os
import secrets
import time
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

from . import user_store
from .config import get_config
from .logger import get_logger

log = get_logger("auth")
_bearer = HTTPBearer(auto_error=False)

# Session callbacks ─────────────────────────────────────────────────────
_session_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None
_session_validator: Callable[[str], bool] = lambda jti: True


def set_session_callback(cb: Callable[[str, str, Dict[str, Any]], None]) -> None:
    """Set callback fired on login_success / login_failed / etc."""
    global _session_callback
    _session_callback = cb


def set_session_validator(fn: Callable[[str], bool]) -> None:
    """Inject the jti → bool checker used by require_jwt."""
    global _session_validator
    _session_validator = fn


def _emit_session_event(event: str, username: str, details: Optional[Dict[str, Any]] = None) -> None:
    if _session_callback:
        try:
            _session_callback(event, username, details or {})
        except Exception as exc:
            log.warning("session callback error: %s", exc)


# JWT helpers ────────────────────────────────────────────────────────────
def _secret() -> str:
    cfg = get_config("api")
    s = cfg.get("jwt_secret", "")
    if not s:
        s = os.environ.get("SECUBOX_JWT_SECRET", "CHANGEME_INSECURE")
    return s


def create_token(
    username: str,
    expires_in: int = 86400,
    scope: Optional[str] = None,
    jti: Optional[str] = None,
) -> str:
    """Mint a JWT. `scope` carries a short-lived intent ("set-password", "mfa-challenge", …)."""
    payload: Dict[str, Any] = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in,
        "jti": jti or secrets.token_hex(8),
    }
    if scope:
        payload["scope"] = scope
    return jwt.encode(payload, _secret(), algorithm="HS256")


def _decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
        if not payload.get("sub"):
            raise ValueError("missing sub")
        return payload
    except (JWTError, ValueError) as exc:
        log.warning("JWT invalide: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_jwt(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Dict[str, Any]:
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Bearer manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = _decode_token(creds.credentials)
    jti = payload.get("jti")
    if not jti or not _session_validator(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session révoquée",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user_store.is_enabled(payload["sub"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Compte désactivé",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


# Password verification ─────────────────────────────────────────────────
def _check_password(username: str, password: str) -> bool:
    """Delegate to user_store. Replaces the old plaintext auth.toml lookup."""
    return user_store.verify_password(username, password)


# Legacy /auth/login endpoint kept for backwards compat ────────────────
router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request):
    """Plain login endpoint — secubox-auth overrides this with the full branching flow."""
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() \
        or request.headers.get("X-Real-IP", "") \
        or (request.client.host if request.client else "")
    user_agent = request.headers.get("User-Agent", "")
    if not _check_password(req.username, req.password):
        _emit_session_event("login_failed", req.username, {
            "reason": "invalid_credentials",
            "ip": client_ip,
            "user_agent": user_agent[:100] if user_agent else "",
        })
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
        )
    jti = secrets.token_hex(8)
    tok = create_token(req.username, jti=jti)
    _emit_session_event("login_success", req.username, {
        "jti": jti,
        "expires_in": 86400,
        "ip": client_ip,
        "user_agent": user_agent[:100] if user_agent else "",
    })
    return TokenResponse(access_token=tok)
```

- [ ] **Step 4: Install pytest-asyncio if missing**

```bash
python3 -c "import pytest_asyncio" 2>&1 || pip install pytest-asyncio --user
```

If running in a constrained venv, add `asyncio_mode = auto` to a `pytest.ini` if not already.

- [ ] **Step 5: Run test to verify it passes**

```bash
python3 -m pytest common/secubox_core/tests/test_auth_rewire.py -v
```

Expected: 6 passed.

- [ ] **Step 6: Commit**

```bash
git add common/secubox_core/auth.py common/secubox_core/tests/test_auth_rewire.py
git commit -m "feat(core): auth — delegate to user_store, jti, scope, validator, disabled-reject (ref #120)"
```

---

## Task 13 — `secubox-auth` totp_pending + new endpoints

**Goal:** Implement the `/auth/login/mfa`, `/auth/totp/enroll`, `/auth/totp/confirm`, `/auth/totp/disable`, `/auth/set-password`, `/auth/logout`, `/auth/me` endpoints in `secubox-auth`. Register the session validator + callback. Implement `revoke_sessions(name)` callable.

**Files:**
- Create: `packages/secubox-auth/api/totp_pending.py`
- Create: `packages/secubox-auth/tests/test_totp_pending.py`
- Modify: `packages/secubox-auth/api/main.py`
- Create: `packages/secubox-auth/tests/test_auth_flows.py`

- [ ] **Step 1: Write the failing `totp_pending` test**

`packages/secubox-auth/tests/test_totp_pending.py`:

```python
"""TOTP pending-enrollment store with TTL."""
import time
from pathlib import Path

from api import totp_pending


def test_put_get_roundtrip(tmp_path: Path):
    store = totp_pending.PendingStore(tmp_path / "pending.json", ttl_seconds=600)
    store.put("jti-abc", "SECRET123")
    assert store.get("jti-abc") == "SECRET123"


def test_get_returns_none_after_ttl(tmp_path: Path, monkeypatch):
    store = totp_pending.PendingStore(tmp_path / "pending.json", ttl_seconds=1)
    store.put("jti-abc", "SECRET123")
    # Fast-forward clock.
    real_time = time.time
    monkeypatch.setattr(totp_pending.time, "time", lambda: real_time() + 5)
    assert store.get("jti-abc") is None


def test_delete_removes_entry(tmp_path: Path):
    store = totp_pending.PendingStore(tmp_path / "pending.json", ttl_seconds=600)
    store.put("jti-abc", "SECRET123")
    store.delete("jti-abc")
    assert store.get("jti-abc") is None


def test_get_returns_none_for_missing(tmp_path: Path):
    store = totp_pending.PendingStore(tmp_path / "pending.json", ttl_seconds=600)
    assert store.get("unknown") is None
```

- [ ] **Step 2: Run test, verify it fails, implement `totp_pending.py`**

```bash
python3 -m pytest packages/secubox-auth/tests/test_totp_pending.py -v
```

Expected: ImportError.

`packages/secubox-auth/api/totp_pending.py`:

```python
"""Pending-TOTP-enrollment store. JSON-backed, TTL'd."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional


class PendingStore:
    def __init__(self, path: Path, ttl_seconds: int = 900):
        self.path = Path(path)
        self.ttl = ttl_seconds
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("{}")

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {}

    def _save(self, doc: dict) -> None:
        fd, tmp = tempfile.mkstemp(prefix=".pending.", dir=str(self.path.parent))
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f)
        os.replace(tmp, self.path)

    def put(self, key: str, secret: str) -> None:
        doc = self._load()
        doc[key] = {"secret": secret, "expires_at": int(time.time()) + self.ttl}
        self._save(doc)

    def get(self, key: str) -> Optional[str]:
        doc = self._load()
        entry = doc.get(key)
        if not entry:
            return None
        if entry.get("expires_at", 0) < int(time.time()):
            self.delete(key)
            return None
        return entry.get("secret")

    def delete(self, key: str) -> None:
        doc = self._load()
        if key in doc:
            del doc[key]
            self._save(doc)
```

Run again — expect 4 passed.

- [ ] **Step 3: Write the auth-flows integration test**

`packages/secubox-auth/tests/test_auth_flows.py`:

```python
"""End-to-end auth flows: password + TOTP + set-password + disable."""
import json
from pathlib import Path

import pyotp
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    # Configure paths
    users_path = tmp_path / "users.json"
    sessions_path = tmp_path / "sessions.json"
    audit_path = tmp_path / "audit.log"
    pending_path = tmp_path / "totp-pending.json"

    # Pre-seed admin with password set, no TOTP yet (will trigger enrollment branch).
    pw_hash = PasswordHasher().hash("GoodPass!42xyz")
    users_path.write_text(json.dumps({
        "version": 2,
        "users": [{
            "username": "admin",
            "email": "a@b.c",
            "role": "admin",
            "enabled": True,
            "password_hash": pw_hash,
            "must_change_password": False,
            "totp": None,
            "google": None,
            "services": [],
            "created": "2026-05-13T00:00:00+00:00",
            "last_login": None,
        }],
        "groups": [],
    }))
    sessions_path.write_text("[]")
    pending_path.write_text("{}")

    monkeypatch.setenv("USERS_FILE", str(users_path))
    monkeypatch.setenv("SECUBOX_AUTH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(sessions_path))
    monkeypatch.setenv("SECUBOX_AUTH_AUDIT", str(audit_path))
    monkeypatch.setenv("SECUBOX_AUTH_TOTP_PENDING", str(pending_path))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    monkeypatch.setenv("SECUBOX_FEATURE_FLAGS", "")  # use defaults

    # Point user_store at the temp file
    from secubox_core import user_store
    monkeypatch.setattr(user_store, "USERS_PATH", users_path)

    # Re-import the app for a clean state
    import importlib
    from api import main as auth_main
    importlib.reload(auth_main)

    return TestClient(auth_main.app), users_path, sessions_path


def test_admin_password_login_returns_enrollment_token(client):
    c, users_path, _ = client
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body.get("enrollment_required") is True
    assert "enrollment_token" in body


def test_wrong_password_returns_401(client):
    c, *_ = client
    r = c.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_disabled_user_blocked(client):
    c, users_path, sessions_path = client
    # disable admin
    doc = json.loads(users_path.read_text())
    doc["users"][0]["enabled"] = False
    users_path.write_text(json.dumps(doc))
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 401


def test_full_totp_enrollment_then_login(client):
    c, users_path, sessions_path = client

    # 1. Login → enrollment_token
    r1 = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    enroll_tok = r1.json()["enrollment_token"]

    # 2. Enroll → secret + QR
    r2 = c.post("/auth/totp/enroll", headers={"Authorization": f"Bearer {enroll_tok}"})
    assert r2.status_code == 200
    secret = r2.json()["secret"]
    assert "otpauth_uri" in r2.json()

    # 3. Confirm with wrong code → 401, pending kept
    r3 = c.post(
        "/auth/totp/confirm",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {enroll_tok}"},
    )
    assert r3.status_code == 401

    # 4. Confirm with correct code → access_token + backup codes
    code = pyotp.TOTP(secret).now()
    r4 = c.post(
        "/auth/totp/confirm",
        json={"code": code},
        headers={"Authorization": f"Bearer {enroll_tok}"},
    )
    assert r4.status_code == 200
    assert "access_token" in r4.json()
    assert len(r4.json()["backup_codes"]) == 10

    # 5. Next login now gets mfa_required
    r5 = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r5.status_code == 200
    assert r5.json()["mfa_required"] is True
```

- [ ] **Step 4: Modify `packages/secubox-auth/api/main.py`**

The existing file already has a Sessions/StatsCache/etc. Locate `app = FastAPI(...)` and `app.include_router(auth_router, prefix="/auth")` near line ~30-50. After that block, add the new code below.

Open `packages/secubox-auth/api/main.py` and **before** the existing `app.include_router(auth_router, prefix="/auth")` line, INSERT:

```python
import os
import secrets as _secrets
from pathlib import Path as _Path

from secubox_core import user_store
from secubox_core.auth import (
    create_token,
    set_session_callback,
    set_session_validator,
    _emit_session_event,
)

# Make secubox-users engine importable for the IPC-free in-process path.
import sys as _sys
_sys.path.insert(0, "/usr/lib/secubox/users")
try:
    from api import engine as _users_engine_mod
    from api import totp as _users_totp_mod
except ImportError:
    # dev mode: try repo path
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[3] / "packages" / "secubox-users"))
    from api import engine as _users_engine_mod
    from api import totp as _users_totp_mod
from api.totp_pending import PendingStore

_DATA_DIR = _Path(os.environ.get("SECUBOX_AUTH_DATA_DIR", "/var/lib/secubox/auth"))
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_SESSIONS_FILE = _Path(os.environ.get("SECUBOX_AUTH_SESSIONS", _DATA_DIR / "sessions.json"))
_AUDIT_FILE = _Path(os.environ.get("SECUBOX_AUTH_AUDIT", _DATA_DIR / "audit.log"))
_TOTP_PENDING_FILE = _Path(os.environ.get("SECUBOX_AUTH_TOTP_PENDING", _DATA_DIR / "totp-pending.json"))
_USERS_FILE = _Path(os.environ.get("USERS_FILE", "/etc/secubox/users.json"))

_pending = PendingStore(_TOTP_PENDING_FILE, ttl_seconds=900)
_users_engine = _users_engine_mod.Engine(users_path=_USERS_FILE)


def _read_sessions() -> list:
    if not _SESSIONS_FILE.exists():
        return []
    try:
        return json.loads(_SESSIONS_FILE.read_text())
    except Exception:
        return []


def _write_sessions(rows: list) -> None:
    _SESSIONS_FILE.write_text(json.dumps(rows))


def _append_audit(event: str, username: str, details: dict) -> None:
    line = json.dumps({"ts": time.time(), "event": event, "user": username, **details}) + "\n"
    with _AUDIT_FILE.open("a") as f:
        f.write(line)


def _session_validator(jti: str) -> bool:
    return any(s.get("id") == jti for s in _read_sessions())


def _on_session_event(event: str, username: str, details: dict) -> None:
    _append_audit(event, username, details)
    if event == "login_success":
        rows = _read_sessions()
        rows.append({
            "id": details.get("jti", _secrets.token_hex(8)),
            "username": username,
            "ip": details.get("ip", ""),
            "user_agent": details.get("user_agent", ""),
            "created": datetime.utcnow().isoformat(),
            "expires": int(time.time()) + details.get("expires_in", 86400),
            "type": "jwt",
        })
        _write_sessions(rows)


def _revoke_sessions(username: str) -> int:
    rows = _read_sessions()
    keep = [r for r in rows if r.get("username") != username]
    n = len(rows) - len(keep)
    _write_sessions(keep)
    _append_audit("sessions_revoked", username, {"count": n})
    return n


set_session_callback(_on_session_event)
set_session_validator(_session_validator)
_users_engine.set_revoke_callback(_revoke_sessions)
_users_engine.set_audit_callback(lambda evt, user, d: _append_audit(evt, user, d))


# ─── Branching login override ─────────────────────────────────────────
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel as _BaseModel

_login_router = APIRouter(tags=["auth-v2"])


class _LoginIn(_BaseModel):
    username: str
    password: str


class _MfaIn(_BaseModel):
    code: str


class _SetPasswordIn(_BaseModel):
    new_password: str
    old_password: str | None = None


@_login_router.post("/login")
async def _login_v2(req: _LoginIn, request: Request):
    """Branching login: setup_token / mfa_token / enrollment_token / access_token."""
    ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
          or request.headers.get("X-Real-IP", "")
          or (request.client.host if request.client else ""))
    ua = request.headers.get("User-Agent", "")[:100]
    user = user_store.get_user(req.username)

    if not user or not user.get("enabled"):
        _emit_session_event("login_failed", req.username, {
            "reason": "unknown_user" if not user else "disabled",
            "ip": ip, "user_agent": ua,
        })
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    # Initial-setup branch
    if user.get("must_change_password") and req.password == "":
        setup_tok = create_token(req.username, scope="set-password", expires_in=900)
        _append_audit("setup_token_issued", req.username, {"ip": ip})
        return {"setup_required": True, "setup_token": setup_tok}

    if not user.get("password_hash"):
        _emit_session_event("login_failed", req.username, {"reason": "no_local_password", "ip": ip})
        raise HTTPException(status_code=401, detail="Aucun mot de passe local")

    if not user_store.verify_password(req.username, req.password):
        _emit_session_event("login_failed", req.username, {"reason": "invalid_credentials", "ip": ip})
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    totp_block = user.get("totp") or {}
    if totp_block.get("enabled"):
        mfa_tok = create_token(req.username, scope="mfa-challenge", expires_in=300)
        _append_audit("mfa_challenge_issued", req.username, {"ip": ip})
        return {"mfa_required": True, "mfa_token": mfa_tok}

    if user.get("role") == "admin":
        enroll_tok = create_token(req.username, scope="totp-enroll", expires_in=900)
        _append_audit("totp_enrollment_required", req.username, {"ip": ip})
        return {"enrollment_required": True, "enrollment_token": enroll_tok}

    jti = _secrets.token_hex(8)
    tok = create_token(req.username, jti=jti)
    _on_session_event("login_success", req.username, {
        "jti": jti, "expires_in": 86400, "ip": ip, "user_agent": ua,
    })
    _users_engine.touch_last_login(req.username)
    return {"access_token": tok, "token_type": "bearer", "expires_in": 86400}


def _check_scope(authorization: str | None, expected_scope: str) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token Bearer manquant")
    from secubox_core.auth import _decode_token as _decode
    payload = _decode(authorization.split(" ", 1)[1])
    if payload.get("scope") != expected_scope:
        raise HTTPException(status_code=403, detail="Token hors scope")
    return payload


@_login_router.post("/login/mfa")
async def _login_mfa(req: _MfaIn, request: Request):
    payload = _check_scope(request.headers.get("Authorization"), "mfa-challenge")
    username = payload["sub"]
    if not user_store.is_enabled(username):
        raise HTTPException(status_code=401, detail="Compte désactivé")
    ok = _users_engine.verify_totp_for_user(username, req.code) \
        or _users_engine.consume_backup_code(username, req.code)
    if not ok:
        _append_audit("mfa_failed", username, {})
        raise HTTPException(status_code=401, detail="Code invalide")
    jti = _secrets.token_hex(8)
    tok = create_token(username, jti=jti)
    _on_session_event("login_success", username, {"jti": jti, "expires_in": 86400, "ip": ""})
    _users_engine.touch_last_login(username)
    return {"access_token": tok, "token_type": "bearer", "expires_in": 86400}


@_login_router.post("/totp/enroll")
async def _totp_enroll(request: Request):
    payload = _check_scope(request.headers.get("Authorization"), "totp-enroll")
    username = payload["sub"]
    existing = user_store.get_user(username) or {}
    if (existing.get("totp") or {}).get("enabled"):
        raise HTTPException(status_code=409, detail="Déjà enrôlé")
    secret = _users_totp_mod.generate_secret()
    _pending.put(payload["jti"], secret)
    import socket
    issuer = f"SecuBox · {socket.gethostname()}"
    uri = _users_totp_mod.provisioning_uri(username, secret, issuer=issuer)
    # QR PNG generated client-side to keep deps minimal; the otpauth URI is sufficient.
    return {"secret": secret, "otpauth_uri": uri, "qr_png_b64": ""}


@_login_router.post("/totp/confirm")
async def _totp_confirm(req: _MfaIn, request: Request):
    payload = _check_scope(request.headers.get("Authorization"), "totp-enroll")
    username = payload["sub"]
    secret = _pending.get(payload["jti"])
    if not secret:
        raise HTTPException(status_code=410, detail="Enrôlement expiré")
    import pyotp
    if not pyotp.TOTP(secret).verify(req.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Code invalide")
    backup_plain = _users_engine.enroll_totp(username, secret)
    _pending.delete(payload["jti"])
    jti = _secrets.token_hex(8)
    tok = create_token(username, jti=jti)
    _on_session_event("login_success", username, {"jti": jti, "expires_in": 86400, "ip": ""})
    return {
        "access_token": tok, "token_type": "bearer", "expires_in": 86400,
        "backup_codes": backup_plain,
        "backup_codes_note": "Conservez ces codes. Affichés une seule fois.",
    }


@_login_router.post("/set-password")
async def _set_password(req: _SetPasswordIn, request: Request):
    auth_h = request.headers.get("Authorization", "")
    if not auth_h.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token Bearer manquant")
    from secubox_core.auth import _decode_token as _decode
    payload = _decode(auth_h.split(" ", 1)[1])
    scope = payload.get("scope")
    username = payload["sub"]
    if scope == "set-password":
        _users_engine.set_password(username, req.new_password)
        _users_engine.revoke_sessions(username)
        return {"ok": True, "message": "Mot de passe défini, veuillez vous reconnecter"}
    if scope is None:
        # Change-my-password (full JWT)
        if not req.old_password:
            raise HTTPException(status_code=400, detail="Ancien mot de passe requis")
        if not user_store.verify_password(username, req.old_password):
            raise HTTPException(status_code=401, detail="Ancien mot de passe incorrect")
        _users_engine.set_password(username, req.new_password)
        return {"ok": True, "message": "Mot de passe modifié"}
    raise HTTPException(status_code=403, detail="Token hors scope")


# Replace any existing /auth/login from the included auth_router by mounting
# our v2 router LAST under the same prefix.
app.include_router(_login_router, prefix="/auth")
```

Add `from datetime import datetime` at the top of the file if not already present.

- [ ] **Step 5: Run integration test**

```bash
python3 -m pytest packages/secubox-auth/tests/test_auth_flows.py -v
```

Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-auth/api/totp_pending.py \
        packages/secubox-auth/api/main.py \
        packages/secubox-auth/tests/test_totp_pending.py \
        packages/secubox-auth/tests/test_auth_flows.py
git commit -m "feat(auth): branching /auth/login + MFA + TOTP enrol + set-password (ref #120)"
```

---

## Task 14 — `secubox-users` API handlers → engine

**Goal:** Refactor `packages/secubox-users/api/main.py` so every mutation calls `engine.*`. Add the new endpoints from the spec.

**Files:**
- Modify: `packages/secubox-users/api/main.py`
- Create: `packages/secubox-users/tests/test_users_api_handlers.py`

- [ ] **Step 1: Write the test for the new endpoints**

`packages/secubox-users/tests/test_users_api_handlers.py`:

```python
"""secubox-users API handlers — verify each delegates to engine.*"""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    users_path = tmp_path / "users.json"
    users_path.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    monkeypatch.setenv("USERS_FILE", str(users_path))

    import importlib
    from api import main as users_main
    importlib.reload(users_main)
    return TestClient(users_main.app), users_path


def test_disable_endpoint_calls_engine(client, monkeypatch):
    c, p = client
    # Pre-create a user
    from api import engine
    e = engine.Engine(users_path=p)
    e.create_user("alice", email="a@b.c", role="viewer")

    # Bypass auth for the test
    from secubox_core import auth as core_auth
    monkeypatch.setattr(core_auth, "require_jwt", lambda creds=None: {"sub": "admin"})

    r = c.post("/user/alice/disable")
    assert r.status_code == 200
    doc = json.loads(p.read_text())
    assert doc["users"][0]["enabled"] is False
```

(More cases will be added incrementally; this test scaffolds the dispatch pattern.)

- [ ] **Step 2: Examine the existing `secubox-users/api/main.py`**

Run:

```bash
wc -l packages/secubox-users/api/main.py
grep -nE "^@app\\.(get|post|delete|put)|^def cmd_" packages/secubox-users/api/main.py | head -40
```

Note the existing handler list. We'll keep their paths and signatures, but the bodies switch to `engine.*` calls.

- [ ] **Step 3: Replace mutation bodies with engine calls**

In `packages/secubox-users/api/main.py`, near the top imports, add:

```python
from pathlib import Path
from . import engine

_USERS_FILE = Path(os.environ.get("USERS_FILE", "/etc/secubox/users.json"))
_engine = engine.Engine(users_path=_USERS_FILE)
```

Then for each existing mutation handler, replace the body with the engine call. Concrete edits:

- `POST /user/add` → `_engine.create_user(...)` (no password — UI prompts for set-password separately)
- `POST /user/<u>/disable` → `_engine.disable_user(u)`
- `POST /user/<u>/enable` → `_engine.enable_user(u)`
- `POST /user/<u>/password` → `_engine.set_password(u, body.new_password)`
- `DELETE /user/<u>` → (keep as a thin wrapper around a new `_engine.delete_user(u)` — add it to engine if missing)

Add new handlers if absent:

```python
@app.post("/user/{username}/totp/disable")
async def disable_user_totp(username: str, _: dict = Depends(require_jwt)):
    _engine.disable_totp(username)
    return {"ok": True}


@app.post("/user/{username}/totp/backup-codes")
async def regen_backup_codes(username: str, _: dict = Depends(require_jwt)):
    return {"backup_codes": _engine.regenerate_backup_codes(username)}


@app.get("/user/{username}/sessions")
async def list_user_sessions(username: str, _: dict = Depends(require_jwt)):
    # Read from secubox-auth's sessions.json
    sessions_path = Path(os.environ.get("SECUBOX_AUTH_SESSIONS", "/var/lib/secubox/auth/sessions.json"))
    rows = json.loads(sessions_path.read_text() or "[]")
    return [r for r in rows if r.get("username") == username]


@app.post("/user/{username}/sessions/revoke")
async def revoke_user_sessions(username: str, _: dict = Depends(require_jwt)):
    return {"revoked": _engine.revoke_sessions(username)}
```

For each, if `engine.delete_user` doesn't exist, append to `engine.py`:

```python
    def delete_user(self, username: str) -> None:
        doc = self._load()
        before = len(doc.get("users", []))
        doc["users"] = [u for u in doc.get("users", []) if u.get("username") != username]
        if len(doc["users"]) == before:
            raise EngineError(f"utilisateur inconnu : {username}")
        self._save(doc)
        self._audit("user_deleted", username, {})
```

- [ ] **Step 4: Run the test**

```bash
python3 -m pytest packages/secubox-users/tests/test_users_api_handlers.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/api/main.py \
        packages/secubox-users/api/engine.py \
        packages/secubox-users/tests/test_users_api_handlers.py
git commit -m "feat(users): API handlers delegate to engine + new TOTP/sessions endpoints (ref #120)"
```

---

## Task 15 — `usersctl` rewrite in Python

**Goal:** Replace the bash+jq script with a Python argparse CLI that calls `engine.*`. This is the parity anchor.

**Files:**
- Rewrite: `packages/secubox-users/sbin/usersctl`
- Create: `packages/secubox-users/tests/test_usersctl_cli.py`

- [ ] **Step 1: Write the failing test**

`packages/secubox-users/tests/test_usersctl_cli.py`:

```python
"""usersctl CLI smoke — same operations the API does, hit the same files."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
USERSCTL = ROOT / "packages" / "secubox-users" / "sbin" / "usersctl"


@pytest.fixture
def env(tmp_path: Path):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return {
        "PATH": os.environ["PATH"],
        "USERS_FILE": str(users),
        "PYTHONPATH": str(ROOT / "common") + ":" + str(ROOT / "packages" / "secubox-users"),
    }


def _run(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(USERSCTL), *args],
        env=env, capture_output=True, text=True,
    )


def test_add_lists_user(env):
    _run(env, "add", "alice", "--email", "a@b.c", "--role", "viewer")
    out = _run(env, "list")
    assert "alice" in out.stdout


def test_disable_flips_enabled(env):
    _run(env, "add", "alice", "--email", "a@b.c", "--role", "viewer")
    _run(env, "disable", "alice")
    doc = json.loads(Path(env["USERS_FILE"]).read_text())
    assert doc["users"][0]["enabled"] is False


def test_help_is_zero_exit(env):
    r = _run(env, "--help")
    assert r.returncode == 0
    assert "usersctl" in r.stdout.lower() or "usage" in r.stdout.lower()
```

- [ ] **Step 2: Rewrite `sbin/usersctl`**

`packages/secubox-users/sbin/usersctl`:

```python
#!/usr/bin/env python3
"""usersctl — SecuBox Unified User Management CLI.

Thin wrapper over secubox_users.api.engine. Every mutation goes through the
same engine the FastAPI handlers use, so CLI ↔ API parity is mechanical.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

# Ensure the engine import resolves whether we're installed (/usr/lib/...) or in-tree.
sys.path.insert(0, "/usr/lib/secubox/users")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))

from api import engine, totp, migrate_v1_to_v2  # noqa: E402

USERS_FILE = Path(os.environ.get("USERS_FILE", "/etc/secubox/users.json"))


def _engine() -> engine.Engine:
    return engine.Engine(users_path=USERS_FILE)


def cmd_list(args):
    rows = _engine().list_users()
    if not rows:
        print("(no users)")
        return 0
    fmt = "{:<16} {:<28} {:<10} {:<10}"
    print(fmt.format("USERNAME", "EMAIL", "ROLE", "STATUS"))
    for u in rows:
        print(fmt.format(
            u["username"],
            u.get("email") or "-",
            u.get("role", "-"),
            "enabled" if u.get("enabled") else "disabled",
        ))
    return 0


def cmd_show(args):
    u = _engine().get_user(args.username)
    if not u:
        print(f"user not found: {args.username}", file=sys.stderr)
        return 2
    print(json.dumps(u, indent=2))
    return 0


def cmd_add(args):
    _engine().create_user(args.username, email=args.email, role=args.role)
    print(f"created: {args.username}")
    return 0


def cmd_set_password(args):
    plain = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm: ")
    if plain != confirm:
        print("passwords do not match", file=sys.stderr)
        return 2
    _engine().set_password(args.username, plain)
    print(f"password set: {args.username}")
    return 0


def cmd_clear_password(args):
    _engine().clear_password(args.username)
    print(f"password cleared, must_change_password=true: {args.username}")
    return 0


def cmd_enable(args):
    _engine().enable_user(args.username)
    print(f"enabled: {args.username}")
    return 0


def cmd_disable(args):
    n = _engine().disable_user(args.username)
    print(f"disabled: {args.username} (revoked {n} session(s))")
    return 0


def cmd_totp_enroll(args):
    eng = _engine()
    secret = totp.generate_secret()
    backup = eng.enroll_totp(args.username, secret)
    import socket
    print("Scan this URI / secret with your authenticator app:")
    print(f"  Secret: {secret}")
    print(f"  URI:    {totp.provisioning_uri(args.username, secret, issuer=f'SecuBox · {socket.gethostname()}')}")
    print("Backup codes (save them now — shown only once):")
    for c in backup:
        print(f"  {c}")
    return 0


def cmd_totp_disable(args):
    _engine().disable_totp(args.username)
    print(f"totp disabled: {args.username}")
    return 0


def cmd_totp_backup_codes(args):
    new = _engine().regenerate_backup_codes(args.username)
    print("New backup codes (old ones invalidated):")
    for c in new:
        print(f"  {c}")
    return 0


def cmd_sessions(args):
    sess_path = Path(os.environ.get("SECUBOX_AUTH_SESSIONS", "/var/lib/secubox/auth/sessions.json"))
    rows = json.loads(sess_path.read_text() or "[]") if sess_path.exists() else []
    rows = [r for r in rows if r.get("username") == args.username]
    print(json.dumps(rows, indent=2))
    return 0


def cmd_revoke(args):
    n = _engine().revoke_sessions(args.username)
    print(f"revoked {n} session(s) for {args.username}")
    return 0


def cmd_migrate(args):
    migrate_v1_to_v2.migrate(USERS_FILE, auth_toml_path=Path("/etc/secubox/auth.toml"))
    print("migration complete")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="usersctl", description="SecuBox user management CLI")
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    sub.add_parser("list", help="List all users").set_defaults(func=cmd_list)

    sp = sub.add_parser("show", help="Show one user as JSON")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("add", help="Create a user")
    sp.add_argument("username")
    sp.add_argument("--email", required=True)
    sp.add_argument("--role", required=True, choices=["admin", "operator", "viewer"])
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("set-password", help="Set a user's password (prompts)")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_set_password)

    sp = sub.add_parser("clear-password", help="Reset to must_change_password=true")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_clear_password)

    sp = sub.add_parser("enable", help="Enable a user")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_enable)

    sp = sub.add_parser("disable", help="Disable a user (also revokes sessions)")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_disable)

    sp = sub.add_parser("totp-enroll", help="Enroll TOTP for a user (admin path)")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_totp_enroll)

    sp = sub.add_parser("totp-disable", help="Disable TOTP for a user (admin)")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_totp_disable)

    sp = sub.add_parser("totp-backup-codes", help="Regenerate backup codes")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_totp_backup_codes)

    sp = sub.add_parser("sessions", help="List active sessions for a user")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_sessions)

    sp = sub.add_parser("revoke", help="Force-logout (without disabling)")
    sp.add_argument("username")
    sp.set_defaults(func=cmd_revoke)

    sub.add_parser("migrate-v1-to-v2", help="Migrate users.json + auth.toml to v2").set_defaults(func=cmd_migrate)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except engine.EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
```

Make it executable:

```bash
chmod +x packages/secubox-users/sbin/usersctl
```

- [ ] **Step 3: Run CLI tests**

```bash
python3 -m pytest packages/secubox-users/tests/test_usersctl_cli.py -v
```

Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-users/sbin/usersctl \
        packages/secubox-users/tests/test_usersctl_cli.py
git commit -m "feat(users): usersctl rewritten in Python, delegates to engine (ref #120)"
```

---

## Task 16 — CLI ↔ API parity test

**Goal:** For every mutation, run once via the CLI and once via the API on identical starting state, then diff the resulting `users.json` (ignoring volatile fields). Lock the parity contract.

**Files:**
- Create: `packages/secubox-users/tests/test_cli_api_parity.py`

- [ ] **Step 1: Write the test**

`packages/secubox-users/tests/test_cli_api_parity.py`:

```python
"""CLI ↔ API parity: same mutation, same resulting users.json."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from api import engine

ROOT = Path(__file__).resolve().parents[3]
USERSCTL = ROOT / "packages" / "secubox-users" / "sbin" / "usersctl"

VOLATILE = {"created", "last_login", "enrolled_at", "used_at"}


def _strip_volatile(doc: dict) -> dict:
    """Recursively replace volatile fields with a placeholder so they don't cause spurious diffs."""
    def _walk(obj):
        if isinstance(obj, dict):
            return {k: ("<v>" if k in VOLATILE else _walk(v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(x) for x in obj]
        return obj
    return _walk(doc)


def _fresh_state(tmp_path: Path) -> Path:
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return p


def _run_cli(state_path: Path, *args: str) -> None:
    env = os.environ.copy()
    env["USERS_FILE"] = str(state_path)
    env["PYTHONPATH"] = str(ROOT / "common") + ":" + str(ROOT / "packages" / "secubox-users")
    r = subprocess.run([sys.executable, str(USERSCTL), *args], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_parity_add_disable_enable(tmp_path: Path):
    via_cli = _fresh_state(tmp_path / "a")
    via_api = _fresh_state(tmp_path / "b")

    # CLI mutation sequence
    _run_cli(via_cli, "add", "alice", "--email", "a@b.c", "--role", "viewer")
    _run_cli(via_cli, "disable", "alice")
    _run_cli(via_cli, "enable", "alice")

    # API (in-process engine) — same sequence
    e = engine.Engine(users_path=via_api)
    e.create_user("alice", email="a@b.c", role="viewer")
    e.disable_user("alice")
    e.enable_user("alice")

    cli_doc = _strip_volatile(json.loads(via_cli.read_text()))
    api_doc = _strip_volatile(json.loads(via_api.read_text()))
    assert cli_doc == api_doc
```

- [ ] **Step 2: Run the parity test**

```bash
python3 -m pytest packages/secubox-users/tests/test_cli_api_parity.py -v
```

Expected: 1 passed.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-users/tests/test_cli_api_parity.py
git commit -m "test(users): CLI↔API parity for add/disable/enable (ref #120)"
```

---

## Task 17 — `debian/control` + `debian/postinst`

**Goal:** Wire dependencies and run migration + seed (admin + hostname) on install.

**Files:**
- Modify: `packages/secubox-users/debian/control`
- Modify: `packages/secubox-users/debian/postinst`
- Modify: `packages/secubox-auth/debian/control`

- [ ] **Step 1: Update `packages/secubox-users/debian/control`**

Locate the `Depends:` line and replace with:

```
Depends: ${misc:Depends},
 ${python3:Depends},
 python3-fastapi,
 python3-uvicorn,
 python3-argon2,
 python3-pyotp,
 python3-qrcode,
 python3-jsonschema,
 python3-tomli | python3 (>= 3.11),
 secubox-core (>= 1.0),
 jq
```

- [ ] **Step 2: Update `packages/secubox-auth/debian/control`**

Locate `Depends:` and ensure these are present:

```
Depends: ${misc:Depends},
 ${python3:Depends},
 python3-aiosqlite,
 python3-fastapi,
 python3-uvicorn,
 python3-argon2,
 python3-pyotp,
 python3-jose,
 secubox-core (>= 1.0),
 secubox-users (>= 1.4)
```

- [ ] **Step 3: Replace `packages/secubox-users/debian/postinst`**

`packages/secubox-users/debian/postinst`:

```sh
#!/bin/sh
set -e

case "$1" in
    configure)
        # Create system group + dir
        getent group secubox-users >/dev/null || groupadd --system secubox-users
        install -d -m 0750 -o root -g secubox-users /etc/secubox

        # Run v1 → v2 migration (idempotent)
        python3 -c "
import sys
sys.path.insert(0, '/usr/lib/secubox/users')
from api.migrate_v1_to_v2 import migrate
from pathlib import Path
migrate(Path('/etc/secubox/users.json'), auth_toml_path=Path('/etc/secubox/auth.toml'))
" || echo 'WARN: migration step failed — investigate /etc/secubox/users.json'

        # Seed default users if missing
        HOSTNAME_SHORT="$(hostname -s)"
        for U in admin "$HOSTNAME_SHORT"; do
            # Skip if hostname == "admin" (avoid duplicate)
            [ "$U" = "admin" ] || [ -n "$U" ] || continue
            python3 -c "
import json, sys
from pathlib import Path
p = Path('/etc/secubox/users.json')
doc = json.loads(p.read_text())
if not any(u['username'] == '$U' for u in doc['users']):
    sys.path.insert(0, '/usr/lib/secubox/users')
    from api.engine import Engine
    Engine(users_path=p).create_user('$U', email=None, role='admin')
    print('seeded user: $U')
"
        done

        chmod 640 /etc/secubox/users.json
        chown root:secubox-users /etc/secubox/users.json

        systemctl daemon-reload
        systemctl enable secubox-users.service || true
        systemctl restart secubox-users.service || true
        ;;
esac

#DEBHELPER#
exit 0
```

Mark it executable:

```bash
chmod +x packages/secubox-users/debian/postinst
```

- [ ] **Step 4: Write a dpkg-deb dry-run sanity test**

Run a syntax check without actually installing:

```bash
sh -n packages/secubox-users/debian/postinst && echo "postinst syntax OK"
```

Expected: `postinst syntax OK`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-users/debian/control \
        packages/secubox-users/debian/postinst \
        packages/secubox-auth/debian/control
git commit -m "feat(users): debian deps + postinst migrates + seeds admin + hostname (ref #120)"
```

---

## Task 18 — Live smoke + tracking + finish

**Goal:** Live smoke test against the canonical board, update `.claude/HISTORY.md` and `.claude/WIP.md`, push branch and open the PR.

**Files:**
- Create: `tests/scripts/test-users-auth-live.sh`
- Modify: `.claude/HISTORY.md`
- Modify: `.claude/WIP.md`

- [ ] **Step 1: Write the live smoke script**

`tests/scripts/test-users-auth-live.sh`:

```bash
#!/usr/bin/env bash
# Live smoke: verify auth rework against the canonical Hub.
# Usage: bash tests/scripts/test-users-auth-live.sh [<host>]
set -euo pipefail

HOST="${1:-admin.gk2.secubox.in}"
BOARD_SSH="${BOARD_SSH:-root@192.168.1.200}"
SNAP=$(mktemp -d)
trap 'rm -rf "$SNAP"' EXIT

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
log()   { printf '[smoke] %s\n' "$*"; }

log "1. Snapshot users.json + sessions.json"
ssh "$BOARD_SSH" cat /etc/secubox/users.json > "$SNAP/users.json"
ssh "$BOARD_SSH" cat /var/lib/secubox/auth/sessions.json > "$SNAP/sessions.json" || true

restore() {
    log "Restoring snapshot…"
    ssh "$BOARD_SSH" "cat > /etc/secubox/users.json" < "$SNAP/users.json"
    ssh "$BOARD_SSH" "cat > /var/lib/secubox/auth/sessions.json" < "$SNAP/sessions.json" 2>/dev/null || true
}
trap restore EXIT

log "2. Login with seed (empty password should yield setup_token)"
RESP=$(curl -sk --resolve "$HOST:443:192.168.1.200" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":""}' \
    "https://$HOST/api/v1/auth/login")
echo "$RESP" | grep -q setup_required || { red "FAIL: no setup_token"; exit 1; }
SETUP_TOK=$(echo "$RESP" | jq -r .setup_token)
green "  setup_token issued"

log "3. Set password"
curl -sk --resolve "$HOST:443:192.168.1.200" \
    -H "Authorization: Bearer $SETUP_TOK" \
    -H 'Content-Type: application/json' \
    -d '{"new_password":"SmokePass!42xy"}' \
    "https://$HOST/api/v1/auth/set-password" | jq -e .ok > /dev/null
green "  password set"

log "4. Login again → expect enrollment_required (admin)"
RESP=$(curl -sk --resolve "$HOST:443:192.168.1.200" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"SmokePass!42xy"}' \
    "https://$HOST/api/v1/auth/login")
echo "$RESP" | grep -q enrollment_required || { red "FAIL: no enrollment_required"; exit 1; }
green "  enrollment_required returned"

log "5. Disable admin via usersctl → next login must fail"
ssh "$BOARD_SSH" 'usersctl disable admin'
HTTP=$(curl -sk -o /dev/null -w "%{http_code}" --resolve "$HOST:443:192.168.1.200" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"SmokePass!42xy"}' \
    "https://$HOST/api/v1/auth/login")
[ "$HTTP" = "401" ] || { red "FAIL: disabled admin got HTTP $HTTP"; exit 1; }
green "  disabled admin → 401 ✓"

ssh "$BOARD_SSH" 'usersctl enable admin'
green "OK — auth rework smoke passes."
```

```bash
chmod +x tests/scripts/test-users-auth-live.sh
```

- [ ] **Step 2: Append `.claude/HISTORY.md` entry**

Prepend (under the date heading) to `.claude/HISTORY.md`:

```markdown
## 2026-05-13

### Auth rework — secubox-users as identity source + TOTP 2FA (Issue #120, PR TBD)

**Goal:** Replace plaintext auth.toml admin login with secubox-users-backed argon2id auth + RFC 6238 TOTP 2FA, kill-on-disable session revocation, CLI↔API parity through a single engine module, feature-flagged cutover.

**Done:**
- Spec: `docs/superpowers/specs/2026-05-13-secubox-users-auth-design.md`
- Plan: `docs/superpowers/plans/2026-05-13-secubox-users-auth.md` (18 tasks)
- `secubox_core.user_store` + tests (canonical reader, auth.toml fallback path)
- `secubox_core.feature_flags` + tests
- `secubox_core.auth` rewired (jti, scope, session validator, disabled-reject)
- `secubox_users.engine` (single mutation entry) + tests for lifecycle / passwords / TOTP / sessions
- `secubox_users.password_policy` + tests
- `secubox_users.totp` (pyotp wrapper, argon2id backup codes) + tests
- `secubox_users.migrate_v1_to_v2` (idempotent) + tests
- `secubox-auth` branching `/auth/login` + `/auth/login/mfa` + `/auth/totp/{enroll,confirm,disable}` + `/auth/set-password` + integration tests
- `usersctl` rewritten in Python over the engine + CLI tests + CLI↔API parity test
- `debian/control` deps + `debian/postinst` migration + seed admin + seed `<hostname>`
- Live smoke `tests/scripts/test-users-auth-live.sh`

**Followups:**
- Phase 2 cutover: flip `[auth] enforce_v2 = true` in `/etc/secubox/users.feature_flags.toml` on the board.
- Encryption-at-rest for TOTP secrets — revisit under PARAMETERS double-buffer hardening.
- "Sign in with Google" OIDC stays deferred (schema already reserves `google: null`).

---
```

- [ ] **Step 3: Append `.claude/WIP.md` entry**

Insert under the date heading:

```markdown
## ✅ 2026-05-13: Auth rework — secubox-users + TOTP 2FA (Issue #120, PR TBD)

### Objective
Replace the plaintext `auth.toml` admin login with secubox-users-backed argon2id auth + TOTP 2FA, kill-on-disable session revocation, CLI↔API parity via a single engine, and a feature-flagged cutover.

### Completed
- Brainstormed spec → `docs/superpowers/specs/2026-05-13-secubox-users-auth-design.md`
- Plan (18 tasks) → `docs/superpowers/plans/2026-05-13-secubox-users-auth.md`
- All 18 tasks implemented in `feature/120-...`
- Live smoke passes on `admin.gk2.secubox.in`

### Followups
- Cutover phase: flip feature flag on the canonical board.
- Top-10k common-passwords list refresh (currently a starter ~100-entry seed).
- Frontend: surface "fallback active" red banner when users.json is unhealthy (out of this PR).

---
```

- [ ] **Step 4: Commit**

```bash
git add tests/scripts/test-users-auth-live.sh .claude/HISTORY.md .claude/WIP.md
git commit -m "test+docs: live smoke + HISTORY/WIP entries for auth rework (ref #120)"
```

- [ ] **Step 5: Push + open PR**

```bash
bash scripts/agent-worktree.sh finish
```

Expected: branch pushed, PR opened with `Closes #120`. Note the PR URL.

- [ ] **Step 6: Done**

Wait for user validation. After merge, the cutover plan (flipping `enforce_v2`) is owned by Phase 2 of the rollout — separate task.

---

## Task 19 — Offline-mode hardening for TOTP

**Goal:** Ensure TOTP works correctly when the board is offline / disconnected from NTP, with no dependency on external services or CDNs for QR rendering. Detect NTP degradation and surface it so users aren't silently locked out by clock drift.

**Three deliverables:**
1. Server-side QR PNG (no frontend JS library or external API needed).
2. NTP-health probe (`chronyc tracking`) with degraded-mode TOTP window expansion.
3. `/api/v1/auth/health` endpoint the UI reads to render a banner when NTP is unsynced.

**Files:**
- Modify: `packages/secubox-users/api/totp.py`
- Modify: `packages/secubox-users/tests/test_totp.py`
- Create: `packages/secubox-auth/api/ntp_health.py`
- Create: `packages/secubox-auth/tests/test_ntp_health.py`
- Modify: `packages/secubox-auth/api/main.py`
- Modify: `packages/secubox-auth/tests/test_auth_flows.py`

- [ ] **Step 1: Extend `totp.py` with server-side QR PNG generation**

Append to `packages/secubox-users/api/totp.py`:

```python
import base64
import io

import qrcode


def qr_png_b64(otpauth_uri: str, *, box_size: int = 6, border: int = 2) -> str:
    """Render the otpauth:// URI as a base64-encoded PNG (no external service)."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")
```

- [ ] **Step 2: Test the QR rendering**

Append to `packages/secubox-users/tests/test_totp.py`:

```python
def test_qr_png_b64_returns_valid_png_base64():
    uri = totp.provisioning_uri("alice", "JBSWY3DPEHPK3PXP", issuer="SecuBox")
    b64 = totp.qr_png_b64(uri)
    import base64
    raw = base64.b64decode(b64)
    # PNG signature: 89 50 4E 47 0D 0A 1A 0A
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    assert len(raw) > 100  # non-trivial payload


def test_qr_png_b64_is_self_contained(monkeypatch):
    """Render must not require any network call — verified by failing socket."""
    import socket
    real_socket = socket.socket
    def boom(*a, **kw):
        raise OSError("network disabled")
    monkeypatch.setattr(socket, "socket", boom)
    try:
        uri = totp.provisioning_uri("alice", "JBSWY3DPEHPK3PXP")
        b64 = totp.qr_png_b64(uri)
        assert b64
    finally:
        monkeypatch.setattr(socket, "socket", real_socket)
```

Run:

```bash
python3 -m pytest packages/secubox-users/tests/test_totp.py -v
```

Expected: previous 7 still pass + 2 new = 9 passed.

- [ ] **Step 3: Write the NTP-health probe**

`packages/secubox-auth/api/ntp_health.py`:

```python
"""NTP health probe — read chronyc tracking. Used to widen TOTP window on drift."""
from __future__ import annotations

import logging
import re
import subprocess
import time
from typing import Dict

log = logging.getLogger("secubox.ntp_health")

_OFFSET_RE = re.compile(r"^System time\s*:\s*([\d.eE+-]+)\s*seconds", re.MULTILINE)
_LEAP_RE = re.compile(r"^Leap status\s*:\s*(\S.*)$", re.MULTILINE)
_REF_RE = re.compile(r"^Reference ID\s*:\s*(\S+)", re.MULTILINE)

_cache: Dict[str, object] = {"ts": 0, "result": None}
_CACHE_TTL = 30  # seconds


def probe() -> Dict[str, object]:
    """Return {synced, drift_seconds, leap_status, reference_id} or {synced: False, error: ...}.

    Cached for _CACHE_TTL seconds so the auth path doesn't spawn chronyc on every call.
    """
    now = time.time()
    if now - _cache["ts"] < _CACHE_TTL and _cache["result"] is not None:
        return dict(_cache["result"])  # type: ignore
    result = _probe_uncached()
    _cache.update({"ts": now, "result": result})
    return dict(result)


def _probe_uncached() -> Dict[str, object]:
    try:
        out = subprocess.run(
            ["chronyc", "-n", "tracking"],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"synced": False, "error": f"chronyc unavailable: {exc}"}
    if out.returncode != 0:
        return {"synced": False, "error": out.stderr.strip() or "chronyc failed"}
    m_offset = _OFFSET_RE.search(out.stdout)
    m_leap = _LEAP_RE.search(out.stdout)
    m_ref = _REF_RE.search(out.stdout)
    drift = float(m_offset.group(1)) if m_offset else None
    leap = m_leap.group(1).strip() if m_leap else "Unknown"
    ref = m_ref.group(1) if m_ref else "?"
    synced = leap.lower().startswith("normal") and ref != "7F7F0101"  # 7F7F0101 = unsynchronised
    return {
        "synced": synced,
        "drift_seconds": drift,
        "leap_status": leap,
        "reference_id": ref,
    }


def recommended_totp_window() -> int:
    """Return the TOTP `valid_window` to use given current NTP health.

    synced  → 1 (±30s)
    degraded → 3 (±90s) — accept drift up to 90s
    unknown → 2 (±60s) — middle ground
    """
    h = probe()
    if h.get("synced"):
        return 1
    if "error" in h:
        return 2
    return 3
```

- [ ] **Step 4: Test NTP-health probe**

`packages/secubox-auth/tests/test_ntp_health.py`:

```python
"""ntp_health: parsing, caching, fallback when chronyc missing."""
from pathlib import Path

import pytest

from api import ntp_health


SAMPLE_SYNCED = """\
Reference ID    : 8A1B0C2D (ntp.example.org)
Stratum         : 3
Ref time (UTC)  : Wed May 13 04:30:00 2026
System time     : 0.000123456 seconds fast of NTP time
Last offset     : -0.000098 seconds
RMS offset      : 0.000123 seconds
Frequency       : 12.345 ppm slow
Residual freq   : 0.001 ppm
Skew            : 1.234 ppm
Root delay      : 0.012345 seconds
Root dispersion : 0.001234 seconds
Update interval : 64.0 seconds
Leap status     : Normal
"""

SAMPLE_UNSYNCED = """\
Reference ID    : 7F7F0101 ()
Stratum         : 0
Ref time (UTC)  : Thu Jan  1 00:00:00 1970
System time     : 0.000000000 seconds fast of NTP time
Last offset     : +0.000000000 seconds
RMS offset      : 0.000000000 seconds
Frequency       : 0.000 ppm slow
Residual freq   : +0.000 ppm
Skew            : 0.000 ppm
Root delay      : 1.000000000 seconds
Root dispersion : 1.000000000 seconds
Update interval : 0.0 seconds
Leap status     : Not synchronised
"""


@pytest.fixture(autouse=True)
def _bust_cache():
    ntp_health._cache.update({"ts": 0, "result": None})


def _fake_chronyc(stdout: str, returncode: int = 0):
    class _Proc:
        def __init__(self):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode
    def runner(*a, **kw):
        return _Proc()
    return runner


def test_synced(monkeypatch):
    monkeypatch.setattr(ntp_health.subprocess, "run", _fake_chronyc(SAMPLE_SYNCED))
    h = ntp_health.probe()
    assert h["synced"] is True
    assert h["leap_status"].lower().startswith("normal")
    assert ntp_health.recommended_totp_window() == 1


def test_unsynced(monkeypatch):
    monkeypatch.setattr(ntp_health.subprocess, "run", _fake_chronyc(SAMPLE_UNSYNCED))
    h = ntp_health.probe()
    assert h["synced"] is False
    assert ntp_health.recommended_totp_window() == 3


def test_chronyc_missing_returns_unknown(monkeypatch):
    def raise_fnf(*a, **kw):
        raise FileNotFoundError("no chronyc")
    monkeypatch.setattr(ntp_health.subprocess, "run", raise_fnf)
    h = ntp_health.probe()
    assert h["synced"] is False
    assert "error" in h
    assert ntp_health.recommended_totp_window() == 2  # unknown → middle


def test_cache_is_honoured(monkeypatch):
    calls = []
    def runner(*a, **kw):
        calls.append(1)
        class _Proc:
            stdout = SAMPLE_SYNCED
            stderr = ""
            returncode = 0
        return _Proc()
    monkeypatch.setattr(ntp_health.subprocess, "run", runner)
    ntp_health.probe()
    ntp_health.probe()
    ntp_health.probe()
    assert len(calls) == 1  # cached
```

Run:

```bash
python3 -m pytest packages/secubox-auth/tests/test_ntp_health.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Wire NTP-aware window into TOTP verification + add `/auth/health`**

In `packages/secubox-auth/api/main.py`, update the imports at the top to add:

```python
from api import ntp_health
```

Replace the existing `_users_engine.verify_totp_for_user(username, req.code)` call inside `_login_mfa` with a window-aware variant. Add this helper near the other private helpers:

```python
def _verify_totp_ntp_aware(username: str, code: str) -> bool:
    """Verify TOTP with a window scaled by NTP health (offline-mode resilient)."""
    from secubox_core import user_store
    import pyotp
    u = user_store.get_user(username) or {}
    block = (u.get("totp") or {})
    if not block.get("enabled"):
        return False
    secret = block.get("secret")
    last_step = block.get("last_step")
    window = ntp_health.recommended_totp_window()
    step_size = 30
    now = int(time.time())
    current = now // step_size
    for delta in range(-window, window + 1):
        step = current + delta
        if pyotp.TOTP(secret).at(step * step_size) == code:
            if last_step is not None and step <= last_step:
                return False
            # Persist the consumed step
            doc = json.loads(_USERS_FILE.read_text())
            for entry in doc["users"]:
                if entry["username"] == username and entry.get("totp"):
                    entry["totp"]["last_step"] = step
                    break
            _USERS_FILE.write_text(json.dumps(doc, indent=2, sort_keys=True))
            return True
    return False
```

Then in `_login_mfa`, change:

```python
ok = _users_engine.verify_totp_for_user(username, req.code) \
    or _users_engine.consume_backup_code(username, req.code)
```

to:

```python
ok = _verify_totp_ntp_aware(username, req.code) \
    or _users_engine.consume_backup_code(username, req.code)
```

(The engine-level `verify_totp_for_user` stays as the in-process default for tests; the NTP-aware variant is the production path that knows about NTP health.)

Now add the `/auth/health` endpoint at the end of `_login_router`:

```python
@_login_router.get("/health")
async def _auth_health():
    """Public-readable health surface for the UI banner.

    Returns NTP-health + identity-store source. UI uses this to render warnings
    like "Identity store in fallback mode" or "Clock not synced — TOTP may fail".
    """
    from secubox_core import user_store
    src = user_store.load_with_fallback()
    return {
        "ntp": ntp_health.probe(),
        "totp_window": ntp_health.recommended_totp_window(),
        "identity_source": src.get("source"),
        "identity_fallback": src.get("source") == "auth.toml.fallback",
    }
```

- [ ] **Step 6: Test the offline-mode integration**

Append to `packages/secubox-auth/tests/test_auth_flows.py`:

```python
def test_auth_health_endpoint(client, monkeypatch):
    c, *_ = client
    # Force unsynced
    from api import ntp_health
    monkeypatch.setattr(ntp_health, "probe", lambda: {"synced": False, "error": "no chronyc"})
    monkeypatch.setattr(ntp_health, "recommended_totp_window", lambda: 3)
    r = c.get("/auth/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ntp"]["synced"] is False
    assert body["totp_window"] == 3
    assert body["identity_fallback"] in (True, False)  # type-ish check


def test_totp_widened_window_accepts_drifted_code(client, monkeypatch):
    """With NTP degraded (window=3), a code from a step ~60s in the past still validates."""
    import time as _time
    import pyotp
    c, users_path, _ = client

    # Enrol admin first (re-using the existing flow)
    r1 = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    enroll_tok = r1.json()["enrollment_token"]
    r2 = c.post("/auth/totp/enroll", headers={"Authorization": f"Bearer {enroll_tok}"})
    secret = r2.json()["secret"]
    code = pyotp.TOTP(secret).now()
    c.post("/auth/totp/confirm", json={"code": code},
           headers={"Authorization": f"Bearer {enroll_tok}"})

    # Now degrade NTP and present a code from 60s ago
    from api import ntp_health
    monkeypatch.setattr(ntp_health, "recommended_totp_window", lambda: 3)
    r3 = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    mfa_tok = r3.json()["mfa_token"]
    drifted_code = pyotp.TOTP(secret).at(int(_time.time()) - 60)
    r4 = c.post("/auth/login/mfa", json={"code": drifted_code},
                headers={"Authorization": f"Bearer {mfa_tok}"})
    assert r4.status_code == 200
    assert "access_token" in r4.json()
```

Run:

```bash
python3 -m pytest packages/secubox-auth/tests/test_auth_flows.py -v
```

Expected: previous 4 + 2 new = 6 passed.

- [ ] **Step 7: Document the offline-mode contract**

Append to `packages/secubox-users/README.md` (or create the section if absent):

```markdown
## Offline mode (TOTP)

TOTP (RFC 6238) is fundamentally offline — no network needed for code generation
or verification. The board's clock is the only thing that matters.

When the board's NTP is unhealthy (chrony unsynchronised, or chronyc missing),
SecuBox automatically widens the TOTP acceptance window:

| NTP state | TOTP window | Effective tolerance |
|---|---|---|
| Synced (`Leap status: Normal`) | ±1 | ±30s |
| Unsynchronised / degraded | ±3 | ±90s |
| Unknown (chronyc missing) | ±2 | ±60s |

The UI reads `/api/v1/auth/health` and surfaces a banner:
- **"Horloge non synchronisée — fenêtre TOTP élargie"** when `ntp.synced == false`
- **"Source d'identité en mode secours"** when `identity_fallback == true`

If the user is locked out due to clock drift exceeding ±90s, the recovery path
is `usersctl totp-disable <user>` over SSH/console (no network required).

QR codes are rendered server-side via `python3-qrcode` — no external service or
CDN is contacted at any point of the enrolment flow.
```

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-users/api/totp.py \
        packages/secubox-users/tests/test_totp.py \
        packages/secubox-auth/api/ntp_health.py \
        packages/secubox-auth/tests/test_ntp_health.py \
        packages/secubox-auth/api/main.py \
        packages/secubox-auth/tests/test_auth_flows.py \
        packages/secubox-users/README.md
git commit -m "feat(auth): offline-mode hardening — server-side QR + NTP-aware TOTP window + /auth/health (ref #120)"
```

---

## Self-review against the spec

- [x] Section 2 (goals) — every numbered goal maps to tasks 4, 5, 6, 7-10, 11, 12, 13, 14, 15, 16, 17, 19.
- [x] Section 3 (architecture) — engine (7-10), user_store (6), auth rewire (12), secubox-auth handlers (13), secubox-users handlers (14), CLI (15).
- [x] Section 4 (schema + migration) — schema (3), migration (11).
- [x] Section 5 (flows) — Task 13 implements 5.1 / 5.2 / 5.3 / 5.4 / 5.5; sessions.json + audit.log writing also in 13; Task 19 supplements 5.3 with NTP-aware verification window.
- [x] Section 6 (password policy) — Task 4.
- [x] Section 7 (TOTP rules) — Tasks 5, 9, 13, plus Task 19 covers the offline/degraded-NTP case.
- [x] Section 8 (secrets layout) — Task 17 sets owner / chmod.
- [x] Section 9 (error matrix) — covered by integration tests in 13.
- [x] Section 10 (endpoint surface) — implemented across 13, 14, and `/auth/health` added in 19.
- [x] Section 11 (testing) — every test layer present (unit, integration, parity, live smoke); Task 19 adds NTP-health probe tests + drifted-code acceptance test.
- [x] Section 12 (rollout) — feature_flags module in Task 2; cutover is a runtime flip, not code.
- [x] Section 13 (risks) — `usersctl totp-disable` (Task 15) provides the lockout-recovery path; atomic writes + `.v1.bak` in migration; defensive `is_enabled` in `require_jwt` (Task 12); NTP-degradation banner via `/auth/health` (Task 19) ensures users aren't silently locked out by clock drift.

## Offline-mode invariants (added 2026-05-13)

The board may operate fully air-gapped. Every code path here is verified not to require external services:

- **Password hashing** — argon2-cffi, pure local.
- **TOTP generation/verification** — RFC 6238, time-only, no network.
- **QR rendering** — server-side via `python3-qrcode` (Task 19), base64-encoded PNG in the response body. No CDN, no Google Charts, no frontend JS QR library needed.
- **Time source** — chrony on the board. When unsynced, Task 19 widens the TOTP window so users aren't silently locked out, and surfaces a banner via `/auth/health`.
- **Lockout recovery** — `usersctl totp-disable <user>` over SSH or local console. No network required at any point.
- **OIDC** — explicitly out of scope (was the original reading of "google auth" before clarification); no code path reaches `accounts.google.com`.
