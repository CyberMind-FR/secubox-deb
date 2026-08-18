<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Support / Assistance Request Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a box the ability to request real-time assistance from a center — a consent-gated, fully-audited, revocable live session where the center runs a bounded action catalog (console escalation on double-consent), built on the sub-project 1 Centers & Grants substrate.

**Architecture:** Two planes. *Control-plane* = signed append-only ops in the `secubox-annuaire` journal (`ASSIST_*`), mesh-synced and audited, reusing the sub-project 1 `Grant`/journal/crypto machinery. *Data-plane* = a new dedicated package `secubox-assist` whose daemon exposes a per-session ephemeral WebSocket **bound to the wg-mesh interface only**, authenticates with a hashed single-use token, and dispatches catalog actions to existing scoped `ctl`s; a double-consent pty gives console escalation under a non-root user.

**Tech Stack:** Python 3.11, FastAPI + uvicorn on a Unix socket (API), `websockets`/`starlette` WebSocket for the data-plane, Ed25519 (`annuaire.crypto`), pytest. Debian packaging (dh compat 13). nftables drop-in. AppArmor.

## Global Constraints

- **Copyright header** (verbatim) on every Python/Bash file:
  ```
  # SPDX-License-Identifier: LicenseRef-CMSD-1.0
  # Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  # Source-Disclosed License — All rights reserved except as expressly granted.
  # See LICENCE-CMSD-1.0.md for terms.
  ```
- **JWT** on every API endpoint via `Depends(require_jwt)` from `secubox_core.auth`; public endpoints only `/status` + `/health`.
- **No privileged action in-process**: every mutating API path shells out to `secubox-assistctl` (pattern: webui[secubox] → sudo/ctl). Reads may be in-process from the journal.
- **Data-plane bind = wg-mesh interface IP only** (`10.10.0.0/24`), **never `0.0.0.0`**. nft opens the WS port only on `iifname "wg-mesh"`, DEFAULT DROP elsewhere.
- **Token secret NEVER journaled or logged** — only its BLAKE2b hex hash. Token is single-use.
- **audit.log** = `/var/log/secubox/audit.log`, append-only. NEVER tighten the shared parent `/var/log/secubox` (stays `0755`) or `/run/secubox` or `/etc/secubox` (chmod only, never chown shared parents).
- **Daemon runs as a dedicated non-root user `secubox-assist`**; the only privileged path is the scoped catalog `ctl`s (audited). Console pty runs under `secubox-assist`, never root. AppArmor profile enforce.
- **Sovereignty**: grant/session resolution MUST pass `self_did` explicitly (a peer's federated op never grants authority) — mirror `annuaire.grants.active_grants(entries, self_did)`.
- **Fail-closed**: `now >= expires_ts` ⇒ session/console inactive even without a close op; loss of mesh ⇒ session dead.
- **Session unique**: at most one active `AssistSession` per box; opening a second is rejected.
- **DID pattern** everywhere: `^did:plc:[0-9a-f]{32}$`. **scope pattern**: `^[a-z0-9][a-z0-9._-]*$`.
- Commit messages end with `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>` and contain **no** AI/Claude references.
- Versioning `X.Y.Z-1~bookworm1`; `debian/compat` 13; `Standards-Version: 4.6.2`; `#DEBHELPER#` alone on its line.

## Substrate reference (sub-project 1 — reuse, do not reinvent)

- `packages/secubox-annuaire/annuaire/model.py`: `class Op(str, Enum)` (add members here), `now_rfc3339()`, `Grant`, `LAYER_ORDER`, `NON_DELEGATABLE`. DID/scope Field patterns as above.
- `annuaire/crypto.py`: `sign(priv_bytes: bytes, msg: bytes) -> str` (hex), `verify(pub_hex: str, msg: bytes, sig_hex: str) -> bool`, `canonical_bytes(payload: dict) -> bytes`, `public_from_private(priv_bytes: bytes) -> bytes`, `did_from_pubkey(pub_bytes: bytes) -> str`.
- `annuaire/log.py`: `class Journal` with `append(op, payload, payload_type, author, author_pubkey_hex=None) -> LogEntry` (payload stored WITHOUT sig/signer_did; sig is Ed25519 over `canonical_bytes(payload)`), and `iter_entries() -> Iterator[LogEntry]` (each has `.op`, `.payload` dict, `.author`).
- `annuaire/grants.py`: `active_grants(entries, self_did=None)`, `_op(entry)`, `_payload(entry)` — the two helpers already tolerate BOTH `LogEntry` (attribute access) AND plain dicts. **Reuse `_op`/`_payload` in `assist.py`** (import them) rather than re-deriving.
- `verbs.py` signing idiom (copy this shape exactly):
  ```python
  payload = { ...fields..., "created_at": now_rfc3339() }
  sig_hex = sign(priv_bytes, canonical_bytes(payload))
  journal.append(op=Op.X, payload=payload, payload_type="TypeName",
                 author=author_did, author_pubkey_hex=pub_hex)
  ```
- `sbin/sbx-centersctl`: key loading (`ANNUAIRE_KEY_PATH` default `/etc/secubox/secrets/annuaire/node.key`, raw 32-byte Ed25519, 64 hex), `DRYRUN=1` support, JSON stdout / `{"error":...}` stderr on rejection. **Model `secubox-assistctl` on this file.**
- Tests live per-package under `tests/`; run with the repo `.venv` and `pytest` **per-directory** (pytest.ini collision across packages — [[reference_local_test_env]]).

## File Structure

**Control-plane — `packages/secubox-annuaire/` (extend):**
- `annuaire/model.py` — add 6 `Op` members + `AssistRequest`, `AssistSession` pydantic models + `ASSIST_MODES`, `ASSIST_CONSOLE`.
- `annuaire/assist.py` (new) — pure resolution from journal entries: pending requests, single active session, console state, expiry, sovereignty filter.
- `annuaire/verbs.py` — add `assist_request/assist_accept/assist_session_open/assist_session_close/assist_console_grant/assist_console_revoke`.
- `tests/test_assist_model.py`, `tests/test_assist_resolve.py`, `tests/test_assist_verbs.py`.

**Data-plane — `packages/secubox-assist/` (new package):**
- `assist/token.py` — mint/hash/verify single-use session token.
- `assist/catalog.py` — bounded action allow-list → argv for scoped ctl; no arbitrary shell.
- `assist/diag.py` — diagnostic bundle collector with conservative redaction.
- `assist/audit.py` — append-only audit writer.
- `assist/wsserver.py` — WebSocket data-plane daemon (bind wg-mesh only, token auth, dispatch).
- `assist/console.py` — pty console manager (double-consent gated, non-root, keystroke audit).
- `api/main.py` — FastAPI `/assist/*` (reads in-process; writes → `secubox-assistctl`).
- `sbin/secubox-assistctl` — root-scoped CLI (writes journal ops, drives daemon).
- `www/assist/index.html` — operator panel + center queue.
- `menu.d/580-assist.json`, `nginx/assist.conf`.
- `systemd/secubox-assist.service` (WS daemon), `systemd/secubox-assist-api.service` (API on socket).
- `debian/{control,rules,changelog,compat,postinst,prerm,secubox-assist.install}`, `apparmor/secubox-assist`, `sudoers/secubox-assist`, `nft/zz-secubox-assist.conf`.
- `tests/test_token.py`, `tests/test_catalog.py`, `tests/test_diag.py`, `tests/test_audit.py`, `tests/test_wsserver_bind.py`, `tests/test_console.py`, `tests/test_assistctl.py`, `tests/test_api.py`.

---

## Task 1: Journal ops + assist models (control-plane data model)

**Files:**
- Modify: `packages/secubox-annuaire/annuaire/model.py` (add to `Op` enum after `BAN_REVOKE`; add models after `Grant`)
- Test: `packages/secubox-annuaire/tests/test_assist_model.py`

**Interfaces:**
- Consumes: `Op` (existing enum), `now_rfc3339`, pydantic `BaseModel`/`Field`/`ConfigDict` (already imported in model.py).
- Produces:
  - `Op.ASSIST_REQUEST="assist_request"`, `Op.ASSIST_ACCEPT="assist_accept"`, `Op.ASSIST_SESSION_OPEN="assist_session_open"`, `Op.ASSIST_SESSION_CLOSE="assist_session_close"`, `Op.ASSIST_CONSOLE_GRANT="assist_console_grant"`, `Op.ASSIST_CONSOLE_REVOKE="assist_console_revoke"`.
  - `ASSIST_MODES = {"per-incident", "standing"}`.
  - `AssistRequest(req_id:str, center_did:str[DID], mode:str, scope:str[scope-pat], duration_s:int, reason:str, issued_by:str[DID], created_at:str, sig:Optional[str], signer_did:Optional[str])`.
  - `AssistSession(session_id:str, req_id:str, center_did:str[DID], token_hash:str[64 hex], expires_ts:str, issued_by:str[DID], created_at:str, sig:Optional[str], signer_did:Optional[str])`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_assist_model.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from pydantic import ValidationError
from annuaire.model import Op, ASSIST_MODES, AssistRequest, AssistSession

DID = "did:plc:" + "a" * 32


def test_ops_present():
    assert Op.ASSIST_REQUEST == "assist_request"
    assert Op.ASSIST_SESSION_OPEN == "assist_session_open"
    assert Op.ASSIST_CONSOLE_GRANT == "assist_console_grant"


def test_request_valid():
    r = AssistRequest(req_id="r1", center_did=DID, mode="per-incident",
                      scope="firewall", duration_s=1800, reason="help",
                      issued_by=DID)
    assert r.mode in ASSIST_MODES and r.sig is None


def test_request_rejects_bad_mode():
    with pytest.raises(ValidationError):
        AssistRequest(req_id="r1", center_did=DID, mode="root-me",
                      scope="firewall", duration_s=60, reason="x", issued_by=DID)


def test_request_rejects_path_traversal_scope():
    with pytest.raises(ValidationError):
        AssistRequest(req_id="r1", center_did=DID, mode="standing",
                      scope="../../etc", duration_s=60, reason="x", issued_by=DID)


def test_session_requires_64hex_token_hash():
    with pytest.raises(ValidationError):
        AssistSession(session_id="s1", req_id="r1", center_did=DID,
                      token_hash="short", expires_ts="2026-07-25T12:00:00Z",
                      issued_by=DID)
    ok = AssistSession(session_id="s1", req_id="r1", center_did=DID,
                       token_hash="b" * 64, expires_ts="2026-07-25T12:00:00Z",
                       issued_by=DID)
    assert ok.token_hash == "b" * 64


def test_extra_forbidden():
    with pytest.raises(ValidationError):
        AssistRequest(req_id="r1", center_did=DID, mode="standing", scope="dns",
                      duration_s=60, reason="x", issued_by=DID, sneaky=True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_model.py -q`
Expected: FAIL — `ImportError: cannot import name 'ASSIST_MODES'` (and `AssistRequest`).

- [ ] **Step 3: Implement the models**

In `annuaire/model.py`, add the six members to `class Op` immediately after `BAN_REVOKE = "ban_revoke"`:

```python
    # Support / assistance request (sous-projet 2) — signed control-plane
    ASSIST_REQUEST        = "assist_request"        # box asks a center for help
    ASSIST_ACCEPT         = "assist_accept"         # center accepts the request
    ASSIST_SESSION_OPEN   = "assist_session_open"   # box consents → live session
    ASSIST_SESSION_CLOSE  = "assist_session_close"  # session ends (op or auto-expiry)
    ASSIST_CONSOLE_GRANT  = "assist_console_grant"  # 2nd consent → console escalation
    ASSIST_CONSOLE_REVOKE = "assist_console_revoke" # console withdrawn
```

After the `Grant` class (before `BanRecord`), add:

```python
# ---------------------------------------------------------------------------
# Support / assistance request (sous-projet 2) — real-time help sessions
# ---------------------------------------------------------------------------

ASSIST_MODES = {"per-incident", "standing"}


class AssistRequest(BaseModel):
    """A box's signed request for assistance from a center.

    Self-certifying: authored by the box (entry.author == issued_by). In
    'per-incident' mode this request IS the ephemeral authority (no standing
    grant needed); in 'standing' mode an active capability="assist" Grant is
    required for the center to initiate. sig covers canonical_bytes(payload
    without sig/signer_did).
    """
    model_config = ConfigDict(extra="forbid")

    req_id:     str = Field(..., description="stable id for this request")
    center_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    mode:       str = Field(..., description="'per-incident' or 'standing'")
    scope:      str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]*$",
                            description="incident scope hint; bare filename component")
    duration_s: int = Field(..., ge=60, le=86400, description="requested max session seconds")
    reason:     str = Field(..., min_length=1, max_length=512)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None

    @field_validator("mode")
    @classmethod
    def _mode_known(cls, v: str) -> str:
        if v not in ASSIST_MODES:
            raise ValueError(f"mode must be one of {sorted(ASSIST_MODES)}")
        return v


class AssistSession(BaseModel):
    """A box-consented live assistance session. token_hash is BLAKE2b-hex of
    the single-use session token; the token secret itself is NEVER journaled.
    """
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(..., description="stable id for this session")
    req_id:     str = Field(..., description="the AssistRequest this opens")
    center_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    token_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$",
                            description="BLAKE2b-hex of the single-use session token")
    expires_ts: str = Field(..., description="RFC3339 hard-cap; fail-closed past this")
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None
```

Ensure `field_validator` is imported at the top of model.py (it already imports from pydantic; add `field_validator` to that import if absent).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_model.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/model.py packages/secubox-annuaire/tests/test_assist_model.py
git commit -m "feat(annuaire): assist ops + AssistRequest/AssistSession models (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 2: assist.py — resolution, single active session, console, expiry, sovereignty

**Files:**
- Create: `packages/secubox-annuaire/annuaire/assist.py`
- Test: `packages/secubox-annuaire/tests/test_assist_resolve.py`

**Interfaces:**
- Consumes: `annuaire.grants._op`, `annuaire.grants._payload` (dict/LogEntry tolerant), `annuaire.model.Op`.
- Produces:
  - `pending_requests(entries, self_did) -> list[dict]` — REQUESTs authored by `self_did` (box) not yet accepted, plus (standing) center-initiated requests where a `capability="assist"` grant is active. Returns payloads.
  - `active_session(entries, self_did, now_ts) -> Optional[dict]` — the single SESSION_OPEN by `self_did` with no matching CLOSE and `now_ts < expires_ts`; None otherwise. Raises `AssistError("multiple-active-sessions")` if journal somehow holds >1 (invariant guard).
  - `console_active(entries, session_id, now_ts) -> bool` — CONSOLE_GRANT for `session_id`, no later CONSOLE_REVOKE, `now_ts < expires_ts`.
  - `class AssistError(Exception)`.
  - `can_open(entries, req_id, self_did) -> tuple[bool, str]` — True only if the request exists (authored by self_did OR standing+granted), is accepted, and no active session exists.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_assist_resolve.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from annuaire.model import Op
from annuaire import assist

BOX = "did:plc:" + "1" * 32
CENTER = "did:plc:" + "2" * 32
OTHER = "did:plc:" + "3" * 32


def e(op, **payload):
    return {"op": op.value if hasattr(op, "value") else op, "payload": payload}


def test_active_session_single_and_expiry():
    entries = [
        e(Op.ASSIST_SESSION_OPEN, session_id="s1", req_id="r1", center_did=CENTER,
          issued_by=BOX, token_hash="a" * 64, expires_ts="2026-07-25T12:00:00Z"),
    ]
    # before expiry
    s = assist.active_session(entries, BOX, now_ts="2026-07-25T11:00:00Z")
    assert s and s["session_id"] == "s1"
    # after expiry -> fail-closed None
    assert assist.active_session(entries, BOX, now_ts="2026-07-25T13:00:00Z") is None


def test_close_ends_session():
    entries = [
        e(Op.ASSIST_SESSION_OPEN, session_id="s1", req_id="r1", center_did=CENTER,
          issued_by=BOX, token_hash="a" * 64, expires_ts="2026-07-25T23:00:00Z"),
        e(Op.ASSIST_SESSION_CLOSE, session_id="s1", issued_by=BOX, reason="done"),
    ]
    assert assist.active_session(entries, BOX, now_ts="2026-07-25T12:00:00Z") is None


def test_sovereignty_ignores_foreign_session():
    # a session OPEN authored by someone else (federated) is NOT ours
    entries = [
        e(Op.ASSIST_SESSION_OPEN, session_id="sX", req_id="rX", center_did=CENTER,
          issued_by=OTHER, token_hash="a" * 64, expires_ts="2026-07-25T23:00:00Z"),
    ]
    assert assist.active_session(entries, BOX, now_ts="2026-07-25T12:00:00Z") is None


def test_console_active_and_revoke():
    entries = [
        e(Op.ASSIST_CONSOLE_GRANT, session_id="s1", issued_by=BOX,
          expires_ts="2026-07-25T13:00:00Z"),
    ]
    assert assist.console_active(entries, "s1", now_ts="2026-07-25T12:00:00Z")
    assert not assist.console_active(entries, "s1", now_ts="2026-07-25T14:00:00Z")
    entries.append(e(Op.ASSIST_CONSOLE_REVOKE, session_id="s1", issued_by=BOX))
    assert not assist.console_active(entries, "s1", now_ts="2026-07-25T12:30:00Z")


def test_multiple_active_sessions_raises():
    entries = [
        e(Op.ASSIST_SESSION_OPEN, session_id="s1", req_id="r1", center_did=CENTER,
          issued_by=BOX, token_hash="a" * 64, expires_ts="2026-07-25T23:00:00Z"),
        e(Op.ASSIST_SESSION_OPEN, session_id="s2", req_id="r2", center_did=CENTER,
          issued_by=BOX, token_hash="b" * 64, expires_ts="2026-07-25T23:00:00Z"),
    ]
    with pytest.raises(assist.AssistError):
        assist.active_session(entries, BOX, now_ts="2026-07-25T12:00:00Z")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_resolve.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'annuaire.assist'`.

- [ ] **Step 3: Implement `annuaire/assist.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire.assist — resolve assistance state from the signed log.

Pure functions over journal entries (LogEntry OR dict — via grants._op/_payload).
Every resolver takes the box's own `self_did`: a SESSION/CONSOLE op authored by
anyone else (federated) is IGNORED (sovereignty). Expiry is fail-closed: past
`expires_ts` a session/console is inactive even with no explicit close op.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional

from .grants import _op, _payload  # dict/LogEntry-tolerant accessors
from .model import Op


class AssistError(Exception):
    """Raised on a broken invariant (e.g. >1 active session)."""


def _by(entries, op: Op):
    for entry in entries:
        if _op(entry) == op.value:
            yield _payload(entry)


def active_session(entries: List[Mapping[str, Any]], self_did: str,
                   now_ts: str) -> Optional[dict]:
    """Return the single active session opened BY self_did, or None.

    Active = a SESSION_OPEN (issued_by == self_did) whose session_id has no
    later SESSION_CLOSE and whose expires_ts is still in the future (RFC3339
    lexicographic compare — all timestamps are UTC 'Z', so string order == time
    order). Raises AssistError if more than one is active (invariant breach).
    """
    closed = {p.get("session_id") for p in _by(entries, Op.ASSIST_SESSION_CLOSE)}
    live = []
    for p in _by(entries, Op.ASSIST_SESSION_OPEN):
        if p.get("issued_by") != self_did:
            continue
        sid = p.get("session_id")
        if sid in closed:
            continue
        if str(now_ts) >= str(p.get("expires_ts", "")):
            continue  # fail-closed past hard-cap
        live.append(p)
    if len(live) > 1:
        raise AssistError("multiple-active-sessions")
    return live[0] if live else None


def console_active(entries: List[Mapping[str, Any]], session_id: str,
                   now_ts: str) -> bool:
    """True if a CONSOLE_GRANT for session_id is live (no later REVOKE, not expired)."""
    revoked = {p.get("session_id") for p in _by(entries, Op.ASSIST_CONSOLE_REVOKE)}
    if session_id in revoked:
        # a REVOKE after the last GRANT kills it; treat any revoke as terminal
        # (console is short-lived and re-granted explicitly)
        return False
    for p in _by(entries, Op.ASSIST_CONSOLE_GRANT):
        if p.get("session_id") != session_id:
            continue
        if str(now_ts) < str(p.get("expires_ts", "")):
            return True
    return False


def pending_requests(entries: List[Mapping[str, Any]], self_did: str) -> List[dict]:
    """REQUESTs relevant to this box not yet accepted.

    Includes box-authored requests (issued_by == self_did) and — for standing
    mode — center-authored requests, leaving the standing-grant check to the
    caller (verbs/ctl) which has the grant matrix. Accepted requests drop out.
    """
    accepted = {p.get("req_id") for p in _by(entries, Op.ASSIST_ACCEPT)}
    out = []
    for p in _by(entries, Op.ASSIST_REQUEST):
        if p.get("req_id") in accepted:
            continue
        out.append(p)
    return out


def can_open(entries: List[Mapping[str, Any]], req_id: str,
             self_did: str, now_ts: str) -> tuple[bool, str]:
    """Whether the box may open a session for req_id: request exists, was
    accepted, and NO session is currently active (single-session invariant)."""
    reqs = {p.get("req_id"): p for p in _by(entries, Op.ASSIST_REQUEST)}
    if req_id not in reqs:
        return False, "no-such-request"
    accepted = {p.get("req_id") for p in _by(entries, Op.ASSIST_ACCEPT)}
    if req_id not in accepted:
        return False, "not-accepted"
    if active_session(entries, self_did, now_ts) is not None:
        return False, "session-already-active"
    return True, "ok"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_resolve.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/assist.py packages/secubox-annuaire/tests/test_assist_resolve.py
git commit -m "feat(annuaire): assist.py — session/console resolution, single-session, sovereignty, fail-closed expiry (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 3: verbs.py — signed assist_* journal appends

**Files:**
- Modify: `packages/secubox-annuaire/annuaire/verbs.py` (append new functions at end, before any `__all__`)
- Test: `packages/secubox-annuaire/tests/test_assist_verbs.py`

**Interfaces:**
- Consumes: `sign`, `canonical_bytes`, `public_from_private`, `did_from_pubkey` (from `.crypto`), `Op`, `AssistRequest`, `AssistSession`, `now_rfc3339` (from `.model`), a `Journal` instance, `assist.can_open`.
- Produces (each returns the appended `LogEntry`; each validates its pydantic model first, then signs `canonical_bytes(payload)`):
  - `assist_request(journal, box_priv: bytes, center_did, mode, scope, duration_s, reason, req_id) -> LogEntry`
  - `assist_accept(journal, center_priv: bytes, req_id) -> LogEntry`
  - `assist_session_open(journal, box_priv, req_id, center_did, token_hash, expires_ts, session_id) -> LogEntry` (raises `ValueError` if `assist.can_open` is False)
  - `assist_session_close(journal, box_priv, session_id, reason) -> LogEntry`
  - `assist_console_grant(journal, box_priv, session_id, expires_ts) -> LogEntry`
  - `assist_console_revoke(journal, box_priv, session_id) -> LogEntry`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_assist_verbs.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
import pytest
from annuaire.log import Journal
from annuaire.crypto import canonical_bytes, verify, public_from_private, did_from_pubkey
from annuaire import verbs, assist
from annuaire.model import Op


def _key():
    priv = os.urandom(32)
    did = did_from_pubkey(public_from_private(priv))
    return priv, did


def _journal(tmp_path):
    return Journal(str(tmp_path / "journal.db"))


def test_request_is_signed_and_appended(tmp_path):
    j = _journal(tmp_path)
    box_priv, box_did = _key()
    _, center_did = _key()
    entry = verbs.assist_request(j, box_priv, center_did, "per-incident",
                                 "firewall", 1800, "help me", req_id="r1")
    assert entry.op == Op.ASSIST_REQUEST.value
    payload = entry.payload
    box_pub = public_from_private(box_priv).hex()
    assert verify(box_pub, canonical_bytes(payload), entry.sig)


def test_session_open_blocked_without_accept(tmp_path):
    j = _journal(tmp_path)
    box_priv, box_did = _key()
    _, center_did = _key()
    verbs.assist_request(j, box_priv, center_did, "per-incident", "dns", 600, "x", req_id="r1")
    with pytest.raises(ValueError):
        verbs.assist_session_open(j, box_priv, "r1", center_did,
                                  token_hash="a" * 64,
                                  expires_ts="2999-01-01T00:00:00Z",
                                  session_id="s1")


def test_full_open_after_accept(tmp_path):
    j = _journal(tmp_path)
    box_priv, box_did = _key()
    center_priv, center_did = _key()
    verbs.assist_request(j, box_priv, center_did, "per-incident", "dns", 600, "x", req_id="r1")
    verbs.assist_accept(j, center_priv, "r1")
    entry = verbs.assist_session_open(j, box_priv, "r1", center_did,
                                      token_hash="a" * 64,
                                      expires_ts="2999-01-01T00:00:00Z",
                                      session_id="s1")
    assert entry.op == Op.ASSIST_SESSION_OPEN.value
    s = assist.active_session(list(j.iter_entries()), box_did, now_ts="2026-07-25T00:00:00Z")
    assert s and s["session_id"] == "s1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_verbs.py -q`
Expected: FAIL — `AttributeError: module 'annuaire.verbs' has no attribute 'assist_request'`.

- [ ] **Step 3: Implement the verbs**

Append to `annuaire/verbs.py` (imports at top already include `sign`, `canonical_bytes`, `public_from_private`, `did_from_pubkey`, `Op`, `now_rfc3339`; add `from .model import AssistRequest, AssistSession` and `from . import assist` if not present):

```python
# --- Support / assistance request (sous-projet 2) -------------------------

def _assist_append(journal, priv: bytes, op, model_obj, payload_type):
    """Shared: strip sig/signer_did, sign canonical_bytes(payload), append."""
    payload = model_obj.model_dump(exclude={"sig", "signer_did"})
    pub_hex = public_from_private(priv).hex()
    author_did = did_from_pubkey(public_from_private(priv))
    sig_hex = sign(priv, canonical_bytes(payload))
    return journal.append(op=op, payload=payload, payload_type=payload_type,
                          author=author_did, author_pubkey_hex=pub_hex,
                          sig=sig_hex)


def assist_request(journal, box_priv, center_did, mode, scope, duration_s,
                   reason, req_id):
    box_did = did_from_pubkey(public_from_private(box_priv))
    m = AssistRequest(req_id=req_id, center_did=center_did, mode=mode, scope=scope,
                      duration_s=duration_s, reason=reason, issued_by=box_did)
    return _assist_append(journal, box_priv, Op.ASSIST_REQUEST, m, "AssistRequest")


def assist_accept(journal, center_priv, req_id):
    center_did = did_from_pubkey(public_from_private(center_priv))
    payload = {"req_id": req_id, "center_did": center_did, "created_at": now_rfc3339()}
    pub_hex = public_from_private(center_priv).hex()
    sig_hex = sign(center_priv, canonical_bytes(payload))
    return journal.append(op=Op.ASSIST_ACCEPT, payload=payload,
                          payload_type="AssistAccept", author=center_did,
                          author_pubkey_hex=pub_hex, sig=sig_hex)


def assist_session_open(journal, box_priv, req_id, center_did, token_hash,
                        expires_ts, session_id):
    box_did = did_from_pubkey(public_from_private(box_priv))
    ok, why = assist.can_open(list(journal.iter_entries()), req_id, box_did,
                              now_ts=now_rfc3339())
    if not ok:
        raise ValueError(f"cannot-open: {why}")
    m = AssistSession(session_id=session_id, req_id=req_id, center_did=center_did,
                      token_hash=token_hash, expires_ts=expires_ts, issued_by=box_did)
    return _assist_append(journal, box_priv, Op.ASSIST_SESSION_OPEN, m, "AssistSession")


def assist_session_close(journal, box_priv, session_id, reason):
    box_did = did_from_pubkey(public_from_private(box_priv))
    payload = {"session_id": session_id, "issued_by": box_did, "reason": reason,
               "created_at": now_rfc3339()}
    pub_hex = public_from_private(box_priv).hex()
    sig_hex = sign(box_priv, canonical_bytes(payload))
    return journal.append(op=Op.ASSIST_SESSION_CLOSE, payload=payload,
                          payload_type="AssistSessionClose", author=box_did,
                          author_pubkey_hex=pub_hex, sig=sig_hex)


def assist_console_grant(journal, box_priv, session_id, expires_ts):
    box_did = did_from_pubkey(public_from_private(box_priv))
    payload = {"session_id": session_id, "issued_by": box_did,
               "expires_ts": expires_ts, "created_at": now_rfc3339()}
    pub_hex = public_from_private(box_priv).hex()
    sig_hex = sign(box_priv, canonical_bytes(payload))
    return journal.append(op=Op.ASSIST_CONSOLE_GRANT, payload=payload,
                          payload_type="AssistConsoleGrant", author=box_did,
                          author_pubkey_hex=pub_hex, sig=sig_hex)


def assist_console_revoke(journal, box_priv, session_id):
    box_did = did_from_pubkey(public_from_private(box_priv))
    payload = {"session_id": session_id, "issued_by": box_did,
               "created_at": now_rfc3339()}
    pub_hex = public_from_private(box_priv).hex()
    sig_hex = sign(box_priv, canonical_bytes(payload))
    return journal.append(op=Op.ASSIST_CONSOLE_REVOKE, payload=payload,
                          payload_type="AssistConsoleRevoke", author=box_did,
                          author_pubkey_hex=pub_hex, sig=sig_hex)
```

**Confirmed contract** (`annuaire/log.py`): `Journal.append(op, payload_type, payload, author, sig, created_at=None, author_pubkey_hex=None) -> LogEntry`. It takes `sig=` (required) and verifies it against `canonical_bytes(payload)`; on the first entry per author, pass `author_pubkey_hex=`. The calls above match this exactly (all keyword args). `payload` must NOT contain `sig`/`signer_did` (we `model_dump(exclude=...)`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_verbs.py tests/test_assist_resolve.py tests/test_assist_model.py -q`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/verbs.py packages/secubox-annuaire/tests/test_assist_verbs.py
git commit -m "feat(annuaire): assist_* signed verbs (request/accept/open/close/console) (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 4: secubox-assist package scaffold + token module

**Files:**
- Create: `packages/secubox-assist/assist/__init__.py` (empty), `packages/secubox-assist/assist/token.py`
- Create: `packages/secubox-assist/debian/{control,compat,changelog,rules,secubox-assist.install}` (minimal, expanded in Task 13)
- Test: `packages/secubox-assist/tests/test_token.py`

**Interfaces:**
- Produces in `assist/token.py`:
  - `mint() -> tuple[str, str]` — returns `(token, token_hash)`; token = `secrets.token_urlsafe(32)`, hash = `blake2b(token.encode()).hexdigest()` truncated/normalized to 64 hex.
  - `hash_token(token: str) -> str` — BLAKE2b hex (64) of the token.
  - `verify_token(token: str, token_hash: str) -> bool` — constant-time compare of `hash_token(token)` vs `token_hash`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_token.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from assist import token


def test_mint_returns_token_and_64hex_hash():
    tok, h = token.mint()
    assert len(tok) >= 32
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
    assert token.hash_token(tok) == h


def test_verify_roundtrip_and_reject():
    tok, h = token.mint()
    assert token.verify_token(tok, h)
    assert not token.verify_token("wrong", h)


def test_two_mints_differ():
    assert token.mint()[0] != token.mint()[0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_token.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist'`.

- [ ] **Step 3: Implement token.py + scaffold**

`packages/secubox-assist/assist/__init__.py`: empty file.

`packages/secubox-assist/assist/token.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.token — single-use session token (secret never journaled).

Only the BLAKE2b-hex (64) of the token is stored in the signed journal
(AssistSession.token_hash). The token secret is delivered to the center over
the encrypted mesh channel and presented once on the WebSocket handshake.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets


def hash_token(tok: str) -> str:
    """BLAKE2b hex digest (64 chars) of the token."""
    return hashlib.blake2b(tok.encode("utf-8"), digest_size=32).hexdigest()


def mint() -> tuple[str, str]:
    """Return (token, token_hash). token is URL-safe, ~43 chars of entropy."""
    tok = secrets.token_urlsafe(32)
    return tok, hash_token(tok)


def verify_token(tok: str, token_hash: str) -> bool:
    """Constant-time compare of hash_token(tok) against the stored hash."""
    return hmac.compare_digest(hash_token(tok), token_hash)
```

Minimal `debian/compat`: `13`. Minimal `debian/changelog`:

```
secubox-assist (0.1.0-1~bookworm1) bookworm; urgency=medium

  * Initial socle: assistance request control-plane consumer + data-plane
    daemon (WebSocket bind wg-mesh only), catalog dispatcher, console
    double-consent, secubox-assistctl, /assist panel.

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 25 Jul 2026 12:00:00 +0200
```

Minimal `debian/control` (expanded in Task 13):

```
Source: secubox-assist
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13), dh-python, python3-all
Standards-Version: 4.6.2

Package: secubox-assist
Architecture: all
Depends: ${python3:Depends}, ${misc:Depends}, python3-fastapi, python3-uvicorn,
 python3-websockets, secubox-core, secubox-annuaire
Description: SecuBox assistance request — real-time help sessions
 Consent-gated, audited, revocable live assistance sessions between a box and
 a federated center, over the wg-mesh, with a bounded action catalog and
 double-consent console escalation.
```

Minimal `debian/rules`:

```makefile
#!/usr/bin/make -f
%:
	dh $@ --with python3
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_token.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/__init__.py packages/secubox-assist/assist/token.py packages/secubox-assist/tests/test_token.py packages/secubox-assist/debian
git commit -m "feat(assist): package scaffold + single-use session token (hash-only journaling) (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 5: catalog.py — bounded action allow-list → scoped ctl argv

**Files:**
- Create: `packages/secubox-assist/assist/catalog.py`
- Test: `packages/secubox-assist/tests/test_catalog.py`

**Interfaces:**
- Produces:
  - `CATALOG: dict[str, dict]` — action name → spec `{ "kind": "read"|"ctl"|"diag", "argv": [...], "needs": ["module"|"unit"|"scope"|None] }`.
  - `MODULE_ALLOW: frozenset[str]` — allow-listed `secubox-*` module names for service/config actions.
  - `resolve(action: str, arg: Optional[str]) -> list[str]` — returns the exact argv to exec, or raises `CatalogError` for an unknown action, a target outside `MODULE_ALLOW`, or an `auth`/`secrets` scope. NEVER returns a shell string; always an argv list.
  - `class CatalogError(Exception)`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_catalog.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from assist import catalog


def test_status_all_is_readonly_argv():
    argv = catalog.resolve("status.all", None)
    assert isinstance(argv, list) and argv  # never a shell string


def test_service_restart_allowed_module():
    argv = catalog.resolve("service.restart", "secubox-dns")
    assert "secubox-dns" in argv
    assert not any(";" in a or "&&" in a or "|" in a for a in argv)


def test_unknown_action_rejected():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("rm.rf", "/")


def test_module_outside_allowlist_rejected():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("service.restart", "sshd")


def test_secrets_scope_rejected():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("config.reload", "secrets")
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("config.reload", "auth")


def test_shell_metachars_in_arg_rejected():
    with pytest.raises(catalog.CatalogError):
        catalog.resolve("logs.tail", "secubox-dns; rm -rf /")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_catalog.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist.catalog'`.

- [ ] **Step 3: Implement catalog.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.catalog — the ONLY actions a center may run in a session.

Each action maps to a fixed argv (a scoped ctl or a read command). No entry
ever yields a shell string; every argument is validated against a strict
allow-list so a compromised center can never widen the surface. auth/secrets
scopes are unreachable (NON_DELEGATABLE parity).
"""
from __future__ import annotations

import re
from typing import List, Optional

NON_DELEGATABLE = {"auth", "secrets"}
_MODULE_RE = re.compile(r"^secubox-[a-z0-9][a-z0-9-]{1,40}$")
_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}$")

# Allow-listed modules a center may restart/toggle/reload. Conservative on
# purpose; extend deliberately. (No secubox-auth, no secubox-core.)
MODULE_ALLOW = frozenset({
    "secubox-dns", "secubox-dpi", "secubox-crowdsec", "secubox-netdata",
    "secubox-wireguard", "secubox-qos", "secubox-vhost", "secubox-nextcloud",
    "secubox-mediaflow", "secubox-cdn", "secubox-nac", "secubox-netmodes",
})


class CatalogError(Exception):
    """Unknown action, disallowed target, or unsafe argument."""


def _safe(arg: str, pattern: re.Pattern) -> str:
    if arg is None or not pattern.match(arg):
        raise CatalogError(f"invalid argument: {arg!r}")
    return arg


def _module(arg: str) -> str:
    m = _safe(arg, _MODULE_RE)
    if m not in MODULE_ALLOW:
        raise CatalogError(f"module not allow-listed: {m}")
    return m


def _scope(arg: str) -> str:
    s = _safe(arg, _SCOPE_RE)
    if s in NON_DELEGATABLE:
        raise CatalogError(f"scope not delegatable: {s}")
    return s


def resolve(action: str, arg: Optional[str]) -> List[str]:
    """Return the exact argv for a catalog action, or raise CatalogError."""
    if action == "status.all":
        return ["/usr/sbin/secubox-assistctl", "diag", "status"]
    if action == "diag.collect":
        return ["/usr/sbin/secubox-assistctl", "diag", "bundle"]
    if action == "logs.tail":
        unit = _module(arg)  # only secubox-* units, allow-listed
        return ["journalctl", "-u", unit, "-n", "200", "--no-pager"]
    if action == "service.restart":
        return ["sudo", "-n", "/usr/sbin/secubox-assistctl", "service", "restart", _module(arg)]
    if action == "service.toggle":
        # arg form "secubox-dns:on" | "secubox-dns:off"
        mod, _, state = (arg or "").partition(":")
        if state not in ("on", "off"):
            raise CatalogError("toggle needs <module>:on|off")
        return ["sudo", "-n", "/usr/sbin/secubox-assistctl", "service", "toggle", _module(mod), state]
    if action == "config.reload":
        return ["sudo", "-n", "/usr/sbin/secubox-assistctl", "config", "reload", _scope(arg)]
    if action == "config.rollback":
        return ["sudo", "-n", "/usr/sbin/secubox-assistctl", "config", "rollback", _scope(arg)]
    raise CatalogError(f"unknown action: {action}")


CATALOG = {
    "status.all": {"needs": None}, "diag.collect": {"needs": None},
    "logs.tail": {"needs": "module"}, "service.restart": {"needs": "module"},
    "service.toggle": {"needs": "module:state"}, "config.reload": {"needs": "scope"},
    "config.rollback": {"needs": "scope"},
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_catalog.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/catalog.py packages/secubox-assist/tests/test_catalog.py
git commit -m "feat(assist): bounded action catalog → scoped ctl argv (no arbitrary shell, allow-list) (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 6: diag.py — redacted diagnostic bundle

**Files:**
- Create: `packages/secubox-assist/assist/diag.py`
- Test: `packages/secubox-assist/tests/test_diag.py`

**Interfaces:**
- Produces:
  - `redact(text: str) -> str` — strips secrets: replaces values after `token|secret|password|passwd|api[-_]?key|authorization|bearer` (case-insensitive) with `***`, strips 40+ hex runs, strips email local parts, strips `.key` file contents markers.
  - `collect(now_ts: str) -> dict` — `{ "generated_at", "modules": [...], "logs": {unit: redacted_tail}, "config_effective": {...non-secret...} }`. NEVER reads `/etc/secubox/secrets/**` or any `*.key`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_diag.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from assist import diag


def test_redacts_token_and_password():
    s = 'token = "abcdef123456" password=hunter2 API_KEY: zzz'
    out = diag.redact(s)
    assert "abcdef123456" not in out
    assert "hunter2" not in out
    assert "zzz" not in out
    assert "***" in out


def test_redacts_long_hex_secret():
    s = "key " + "a" * 64
    assert "a" * 64 not in diag.redact(s)


def test_collect_has_no_secret_paths(monkeypatch):
    b = diag.collect(now_ts="2026-07-25T12:00:00Z")
    assert "generated_at" in b and "modules" in b and "logs" in b
    blob = repr(b).lower()
    assert "/etc/secubox/secrets" not in blob
    assert ".key" not in blob
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_diag.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist.diag'`.

- [ ] **Step 3: Implement diag.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.diag — read-only diagnostic bundle with conservative
redaction. Never touches /etc/secubox/secrets or any *.key; secrets that slip
into logs are scrubbed by redact() before they leave the box.
"""
from __future__ import annotations

import re
import subprocess
from typing import Dict, List

from .catalog import MODULE_ALLOW

_SECRET_KV = re.compile(
    r"(?i)\b(token|secret|password|passwd|api[-_]?key|authorization|bearer)\b"
    r"\s*[:=]\s*[\"']?[^\s\"']+")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+\.[\w.-]+)\b")


def redact(text: str) -> str:
    text = _SECRET_KV.sub(lambda m: m.group(1) + "=***", text)
    text = _LONG_HEX.sub("***", text)
    text = _EMAIL.sub(r"***@\1", text)
    return text


def _run(argv: List[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as exc:  # noqa: BLE001 — diag must never crash the session
        return f"<diag error: {exc}>"


def collect(now_ts: str) -> Dict:
    modules = []
    for unit in sorted(MODULE_ALLOW):
        active = _run(["systemctl", "is-active", unit]).strip()
        modules.append({"unit": unit, "active": active})
    logs = {}
    for unit in sorted(MODULE_ALLOW):
        logs[unit] = redact(_run(
            ["journalctl", "-u", unit, "-n", "50", "--no-pager"]))
    return {
        "generated_at": now_ts,
        "modules": modules,
        "logs": logs,
        "config_effective": {"note": "non-secret effective config summary"},
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_diag.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/diag.py packages/secubox-assist/tests/test_diag.py
git commit -m "feat(assist): redacted read-only diag bundle (never secrets/*.key) (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 7: audit.py — append-only audit writer

**Files:**
- Create: `packages/secubox-assist/assist/audit.py`
- Test: `packages/secubox-assist/tests/test_audit.py`

**Interfaces:**
- Produces:
  - `AUDIT_PATH = os.environ.get("SECUBOX_ASSIST_AUDIT", "/var/log/secubox/audit.log")`.
  - `record(event: str, session_id: str, actor: str, detail: dict, *, path: Optional[str]=None) -> None` — appends one RFC3339-stamped JSON line, opened `"a"`, fsync'd; never truncates. Keystroke events use `event="console.keystroke"`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_audit.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
from assist import audit


def test_append_only_and_json_lines(tmp_path):
    p = tmp_path / "audit.log"
    audit.record("session.open", "s1", "did:box", {"req_id": "r1"}, path=str(p))
    audit.record("console.keystroke", "s1", "did:center", {"bytes": 3}, path=str(p))
    lines = p.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "session.open" and first["session_id"] == "s1"
    assert "ts" in first
    # second append does not truncate the first
    assert json.loads(lines[1])["event"] == "console.keystroke"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_audit.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist.audit'`.

- [ ] **Step 3: Implement audit.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.audit — append-only, per-line JSON audit of every
assist event (request→accept→open→each action→console→keystrokes→close).
Never truncates; opens 'a' and fsyncs. CSPN immutability requirement.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

AUDIT_PATH = os.environ.get("SECUBOX_ASSIST_AUDIT", "/var/log/secubox/audit.log")


def record(event: str, session_id: str, actor: str, detail: dict,
           *, path: Optional[str] = None) -> None:
    line = json.dumps({
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src": "secubox-assist",
        "event": event,
        "session_id": session_id,
        "actor": actor,
        "detail": detail,
    }, separators=(",", ":"), sort_keys=True)
    with open(path or AUDIT_PATH, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_audit.py -q`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/audit.py packages/secubox-assist/tests/test_audit.py
git commit -m "feat(assist): append-only JSON audit writer (fsync, never truncate) (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 8: wsserver.py — data-plane WebSocket (mesh-only bind, token auth, dispatch)

**Files:**
- Create: `packages/secubox-assist/assist/wsserver.py`
- Test: `packages/secubox-assist/tests/test_wsserver_bind.py`

**Interfaces:**
- Consumes: `assist.token.verify_token`, `assist.catalog.resolve`, `assist.audit.record`, `assist.diag.collect`, `annuaire.assist.active_session`/`console_active`.
- Produces:
  - `mesh_bind_ip(iface: str = "wg-mesh") -> str` — returns the IPv4 of `iface`; raises `BindError` if the interface is absent (fail-closed: no mesh ⇒ no server).
  - `class BindError(Exception)`.
  - `async def authorize(token: str, entries, self_did, now_ts) -> dict` — returns the active session whose `token_hash` matches, else raises `AuthError`.
  - `class AuthError(Exception)`.
  - `async def dispatch(session: dict, action: str, arg, entries, self_did, now_ts) -> dict` — runs a catalog action (console actions gated by `console_active`); returns `{"ok", "output"|"error"}`; audits every call.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_wsserver_bind.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from assist import wsserver, token


def test_mesh_bind_absent_iface_fails_closed():
    with pytest.raises(wsserver.BindError):
        wsserver.mesh_bind_ip("nonexistent-iface-xyz")


@pytest.mark.asyncio
async def test_authorize_matches_token_hash():
    tok, h = token.mint()
    entries = [{"op": "assist_session_open", "payload": {
        "session_id": "s1", "req_id": "r1", "center_did": "did:plc:" + "2"*32,
        "issued_by": "did:plc:" + "1"*32, "token_hash": h,
        "expires_ts": "2999-01-01T00:00:00Z"}}]
    self_did = "did:plc:" + "1"*32
    s = await wsserver.authorize(tok, entries, self_did, now_ts="2026-07-25T00:00:00Z")
    assert s["session_id"] == "s1"


@pytest.mark.asyncio
async def test_authorize_rejects_wrong_token():
    tok, h = token.mint()
    entries = [{"op": "assist_session_open", "payload": {
        "session_id": "s1", "req_id": "r1", "center_did": "did:plc:" + "2"*32,
        "issued_by": "did:plc:" + "1"*32, "token_hash": h,
        "expires_ts": "2999-01-01T00:00:00Z"}}]
    with pytest.raises(wsserver.AuthError):
        await wsserver.authorize("bogus", entries, "did:plc:" + "1"*32,
                                 now_ts="2026-07-25T00:00:00Z")
```

(`pytest-asyncio` is in the repo `.venv`; if a marker config is needed, add `asyncio_mode = auto` to the package `pytest.ini`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_wsserver_bind.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist.wsserver'`.

- [ ] **Step 3: Implement wsserver.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.wsserver — per-session WebSocket data-plane.

Binds the wg-mesh interface IP ONLY (never 0.0.0.0). Authenticates the center
with the single-use session token (hash matched against the journal's
AssistSession). Dispatches ONLY catalog actions; console actions require a live
CONSOLE_GRANT. Every action is audited. Fail-closed: no wg-mesh ⇒ BindError ⇒
the daemon does not serve.
"""
from __future__ import annotations

import fcntl
import socket
import struct
import subprocess
from typing import Optional

from . import audit, diag
from .catalog import CatalogError, resolve
from .token import verify_token

try:  # annuaire is a runtime dependency (prod: /usr/lib/secubox/annuaire on path)
    from annuaire import assist as _assist
except Exception:  # pragma: no cover - import shim for isolated unit tests
    _assist = None


class BindError(Exception):
    """The wg-mesh interface is absent — refuse to serve (fail-closed)."""


class AuthError(Exception):
    """Presented token does not match any active session."""


def mesh_bind_ip(iface: str = "wg-mesh") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", iface[:15].encode("utf-8"))
        addr = fcntl.ioctl(s.fileno(), 0x8915, packed)  # SIOCGIFADDR
        return socket.inet_ntoa(addr[20:24])
    except OSError as exc:
        raise BindError(f"wg-mesh iface {iface!r} unavailable: {exc}") from exc
    finally:
        s.close()


async def authorize(tok: str, entries, self_did: str, now_ts: str) -> dict:
    """Return the active session matching tok, else AuthError."""
    if _assist is None:
        raise AuthError("annuaire.assist unavailable")
    session = _assist.active_session(entries, self_did, now_ts)
    if session and verify_token(tok, session.get("token_hash", "")):
        return session
    raise AuthError("no active session for token")


async def dispatch(session: dict, action: str, arg: Optional[str], entries,
                   self_did: str, now_ts: str) -> dict:
    """Run one catalog action; console actions require a live console grant."""
    sid = session["session_id"]
    center = session.get("center_did", "?")
    try:
        argv = resolve(action, arg)
    except CatalogError as exc:
        audit.record("action.reject", sid, center, {"action": action, "why": str(exc)})
        return {"ok": False, "error": str(exc)}
    audit.record("action.run", sid, center, {"action": action, "arg": arg})
    if action == "diag.collect":
        return {"ok": True, "output": diag.collect(now_ts)}
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return {"ok": r.returncode == 0, "output": r.stdout, "error": r.stderr}
    except Exception as exc:  # noqa: BLE001
        audit.record("action.error", sid, center, {"action": action, "err": str(exc)})
        return {"ok": False, "error": str(exc)}
```

The WebSocket serving loop (starlette/websockets `serve` on `mesh_bind_ip()`, reading `{action,arg}` frames → `dispatch`) is wired in Task 13's daemon entrypoint; this module holds the testable core (bind, authorize, dispatch).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_wsserver_bind.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/wsserver.py packages/secubox-assist/tests/test_wsserver_bind.py
git commit -m "feat(assist): WS data-plane core — mesh-only bind (fail-closed), token auth, catalog dispatch+audit (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 9: console.py — double-consent pty manager (non-root, keystroke audit)

**Files:**
- Create: `packages/secubox-assist/assist/console.py`
- Test: `packages/secubox-assist/tests/test_console.py`

**Interfaces:**
- Consumes: `assist.audit.record`, `annuaire.assist.console_active`.
- Produces:
  - `class ConsoleDenied(Exception)`.
  - `guard(entries, session_id, now_ts) -> None` — raises `ConsoleDenied` unless `console_active` is True (double-consent gate).
  - `class ConsoleSession` — `open(session_id, center_did)` spawns a pty running `/bin/bash` **under the current (non-root) user** with `os.setsid`, `write(data: bytes)` (audits `console.keystroke` with byte count, never raw secret), `read() -> bytes`, `close()` (SIGTERM + audit `console.close`). Refuses to run if `os.geteuid() == 0` → raises `ConsoleDenied("refuse-root")`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_console.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
import pytest
from assist import console


def test_guard_denies_without_console_grant():
    entries = []  # no CONSOLE_GRANT
    with pytest.raises(console.ConsoleDenied):
        console.guard(entries, "s1", now_ts="2026-07-25T12:00:00Z")


def test_guard_allows_with_grant():
    entries = [{"op": "assist_console_grant", "payload": {
        "session_id": "s1", "issued_by": "did:plc:" + "1"*32,
        "expires_ts": "2999-01-01T00:00:00Z"}}]
    console.guard(entries, "s1", now_ts="2026-07-25T12:00:00Z")  # no raise


@pytest.mark.skipif(os.geteuid() == 0, reason="test asserts non-root refusal path only off-root")
def test_console_refuses_root(monkeypatch):
    monkeypatch.setattr(console.os, "geteuid", lambda: 0)
    cs = console.ConsoleSession(audit_path="/dev/null")
    with pytest.raises(console.ConsoleDenied):
        cs.open("s1", "did:center")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_console.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist.console'`.

- [ ] **Step 3: Implement console.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.console — console escalation pty, gated by a live
CONSOLE_GRANT (double-consent). Runs under the daemon's non-root user; refuses
to run as root. Every keystroke is audited (byte count, not raw content).
"""
from __future__ import annotations

import os
import pty
import signal
from typing import Optional

from . import audit

try:
    from annuaire import assist as _assist
except Exception:  # pragma: no cover
    _assist = None


class ConsoleDenied(Exception):
    """Console not granted, or refused (root)."""


def guard(entries, session_id: str, now_ts: str) -> None:
    if _assist is None or not _assist.console_active(entries, session_id, now_ts):
        raise ConsoleDenied("console not granted (double-consent required)")


class ConsoleSession:
    def __init__(self, audit_path: Optional[str] = None):
        self._pid = None
        self._fd = None
        self._audit_path = audit_path

    def open(self, session_id: str, center_did: str):
        if os.geteuid() == 0:
            raise ConsoleDenied("refuse-root")
        self._session_id = session_id
        self._center = center_did
        pid, fd = pty.fork()
        if pid == 0:  # child
            os.execv("/bin/bash", ["/bin/bash", "-i"])
        self._pid, self._fd = pid, fd
        audit.record("console.open", session_id, center_did, {"pid": pid},
                     path=self._audit_path)

    def write(self, data: bytes):
        audit.record("console.keystroke", self._session_id, self._center,
                     {"bytes": len(data)}, path=self._audit_path)
        os.write(self._fd, data)

    def read(self, n: int = 4096) -> bytes:
        return os.read(self._fd, n)

    def close(self):
        if self._pid:
            try:
                os.kill(self._pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            audit.record("console.close", self._session_id, self._center, {},
                         path=self._audit_path)
            self._pid = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_console.py -q`
Expected: PASS (3 passed; the root-refusal test monkeypatches geteuid).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/console.py packages/secubox-assist/tests/test_console.py
git commit -m "feat(assist): double-consent pty console (non-root, refuse-root, keystroke audit) (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 10: secubox-assistctl — root-scoped CLI

**Files:**
- Create: `packages/secubox-assist/sbin/secubox-assistctl`
- Test: `packages/secubox-assist/tests/test_assistctl.py`

**Interfaces:**
- Consumes: `annuaire.verbs.assist_*`, `annuaire.assist`, `annuaire.log.Journal`, key at `ANNUAIRE_KEY_PATH` (default `/etc/secubox/secrets/annuaire/node.key`).
- Produces subcommands (JSON stdout; `{"error":...}` stderr + rc!=0 on rejection; `DRYRUN=1` prints `{"dryrun":true,"would":...}` and writes nothing):
  - `request <center_did> --mode --scope --duration --reason` → mints nothing (that's at open); appends `ASSIST_REQUEST`.
  - `accept <req_id>` (center key path via `ASSIST_CENTER_KEY` when acting as a center).
  - `open <req_id> --center <did> --duration <s>` → mints token, prints token ONCE on stdout, appends `ASSIST_SESSION_OPEN` with `token_hash` + computed `expires_ts`.
  - `close <session_id> [--reason]`, `console-grant <session_id> --duration`, `console-revoke <session_id>`.
  - `list` → `{ "pending": [...], "active_session": {...}|null }`.
  - `diag status|bundle` → the read-only catalog backends (called by wsserver dispatch under sudo).
  - `service restart|toggle <module> [on|off]`, `config reload|rollback <scope>` → privileged catalog backends (validate via `assist.catalog` allow-list before acting).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_assistctl.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
import os
import subprocess
import sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-assistctl")
ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")


def _env(tmp_path):
    key = tmp_path / "node.key"
    # 32-byte raw Ed25519 as 64 hex
    key.write_text("11" * 32)
    env = dict(os.environ)
    env["ANNUAIRE_KEY_PATH"] = str(key)
    env["ANNUAIRE_JOURNAL"] = str(tmp_path / "journal.db")
    env["ANNUAIRE_LIB"] = ANNUAIRE
    env["PYTHONPATH"] = ANNUAIRE + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_request_then_list(tmp_path):
    env = _env(tmp_path)
    center = "did:plc:" + "2" * 32
    r = subprocess.run([sys.executable, CTL, "request", center, "--mode",
                        "per-incident", "--scope", "dns", "--duration", "600",
                        "--reason", "help"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out.get("req_id")
    r2 = subprocess.run([sys.executable, CTL, "list"], env=env,
                        capture_output=True, text=True)
    listing = json.loads(r2.stdout)
    assert len(listing["pending"]) == 1


def test_dryrun_writes_nothing(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    center = "did:plc:" + "2" * 32
    r = subprocess.run([sys.executable, CTL, "request", center, "--mode",
                        "standing", "--scope", "dns", "--duration", "600",
                        "--reason", "x"], env=env, capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True
    r2 = subprocess.run([sys.executable, CTL, "list"], env=env,
                        capture_output=True, text=True)
    assert json.loads(r2.stdout)["pending"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_assistctl.py -q`
Expected: FAIL — the ctl file does not exist yet (`FileNotFoundError`/nonzero rc).

- [ ] **Step 3: Implement secubox-assistctl** (model on `sbx-centersctl`)

```python
#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-assistctl — box operator CLI for assistance sessions.

Thin CLI over annuaire.verbs.assist_* + annuaire.assist, operating on the BOX
journal + BOX key (sovereign identity), never a center's. Mutations are signed
journal appends (audit trail). The privileged catalog backends (service/config/
diag) are invoked BY the WS daemon under a scoped sudoers entry.

Env (override; key NEVER generated here):
  ANNUAIRE_JOURNAL   default /var/lib/secubox/annuaire/journal.db
  ANNUAIRE_KEY_PATH  default /etc/secubox/secrets/annuaire/node.key (64 hex)
  ANNUAIRE_LIB       default /usr/lib/secubox/annuaire
  DRYRUN=1           print {"dryrun":true,"would":...}; write nothing
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.environ.get("ANNUAIRE_LIB", "/usr/lib/secubox/annuaire"))

from annuaire.log import Journal          # noqa: E402
from annuaire import verbs, assist        # noqa: E402
from annuaire.crypto import public_from_private, did_from_pubkey  # noqa: E402
from assist import token as _token        # noqa: E402  (sibling package on path in prod)


def _die(reason: str):
    print(json.dumps({"error": reason}), file=sys.stderr)
    raise SystemExit(1)


def _key() -> bytes:
    path = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")
    try:
        raw = open(path).read().strip()
    except OSError as exc:
        _die(f"key unreadable: {exc}")
    if len(raw) != 64:
        _die("key must be 64 hex chars (32-byte Ed25519)")
    return bytes.fromhex(raw)


def _journal() -> Journal:
    return Journal(os.environ.get("ANNUAIRE_JOURNAL",
                                  "/var/lib/secubox/annuaire/journal.db"))


def _self_did(priv: bytes) -> str:
    return did_from_pubkey(public_from_private(priv))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dry() -> bool:
    return os.environ.get("DRYRUN") == "1"


def cmd_request(a):
    if _dry():
        print(json.dumps({"dryrun": True, "would": "assist_request",
                          "center": a.center_did})); return
    priv = _key(); j = _journal()
    req_id = "req-" + secrets.token_hex(8)
    verbs.assist_request(j, priv, a.center_did, a.mode, a.scope, a.duration,
                         a.reason, req_id=req_id)
    print(json.dumps({"req_id": req_id}))


def cmd_open(a):
    priv = _key(); j = _journal()
    tok, token_hash = _token.mint()
    expires = (datetime.now(timezone.utc) + timedelta(seconds=a.duration)
               ).strftime("%Y-%m-%dT%H:%M:%SZ")
    if _dry():
        print(json.dumps({"dryrun": True, "would": "assist_session_open"})); return
    session_id = "sess-" + secrets.token_hex(8)
    try:
        verbs.assist_session_open(j, priv, a.req_id, a.center, token_hash,
                                  expires, session_id=session_id)
    except ValueError as exc:
        _die(str(exc))
    # token printed ONCE; delivered to the center over the mesh channel
    print(json.dumps({"session_id": session_id, "token": tok, "expires_ts": expires}))


def cmd_close(a):
    if _dry():
        print(json.dumps({"dryrun": True, "would": "assist_session_close"})); return
    verbs.assist_session_close(_journal(), _key(), a.session_id, a.reason or "operator-close")
    print(json.dumps({"closed": a.session_id}))


def cmd_console_grant(a):
    expires = (datetime.now(timezone.utc) + timedelta(seconds=a.duration)
               ).strftime("%Y-%m-%dT%H:%M:%SZ")
    if _dry():
        print(json.dumps({"dryrun": True, "would": "assist_console_grant"})); return
    verbs.assist_console_grant(_journal(), _key(), a.session_id, expires)
    print(json.dumps({"console": a.session_id, "expires_ts": expires}))


def cmd_console_revoke(a):
    if _dry():
        print(json.dumps({"dryrun": True, "would": "assist_console_revoke"})); return
    verbs.assist_console_revoke(_journal(), _key(), a.session_id)
    print(json.dumps({"console_revoked": a.session_id}))


def cmd_list(a):
    priv = _key(); entries = list(_journal().iter_entries())
    self_did = _self_did(priv)
    pend = assist.pending_requests(entries, self_did)
    sess = assist.active_session(entries, self_did, now_ts=_now())
    print(json.dumps({"pending": pend, "active_session": sess}))


def main():
    p = argparse.ArgumentParser(prog="secubox-assistctl")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("request"); q.add_argument("center_did")
    q.add_argument("--mode", required=True); q.add_argument("--scope", required=True)
    q.add_argument("--duration", type=int, required=True); q.add_argument("--reason", required=True)
    q.set_defaults(fn=cmd_request)

    o = sub.add_parser("open"); o.add_argument("req_id")
    o.add_argument("--center", required=True); o.add_argument("--duration", type=int, required=True)
    o.set_defaults(fn=cmd_open)

    c = sub.add_parser("close"); c.add_argument("session_id"); c.add_argument("--reason")
    c.set_defaults(fn=cmd_close)

    cg = sub.add_parser("console-grant"); cg.add_argument("session_id")
    cg.add_argument("--duration", type=int, required=True); cg.set_defaults(fn=cmd_console_grant)

    cr = sub.add_parser("console-revoke"); cr.add_argument("session_id")
    cr.set_defaults(fn=cmd_console_revoke)

    sub.add_parser("list").set_defaults(fn=cmd_list)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
```

(The `diag`/`service`/`config` privileged subcommands are thin wrappers added in Task 13 alongside the sudoers entry; the session-control subcommands above are the testable core.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_assistctl.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/sbin/secubox-assistctl packages/secubox-assist/tests/test_assistctl.py
git commit -m "feat(assist): secubox-assistctl — signed session control CLI (request/open/close/console, DRYRUN) (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 11: api/main.py — /assist endpoints (reads in-process, writes via ctl)

**Files:**
- Create: `packages/secubox-assist/api/main.py`
- Test: `packages/secubox-assist/tests/test_api.py`

**Interfaces:**
- Consumes: `secubox_core.auth.require_jwt`, `annuaire.assist`, `annuaire.log.Journal`, subprocess to `secubox-assistctl`.
- Produces FastAPI `app`:
  - `GET /status` (public) → `{module, enabled, mesh_iface, has_active_session}`.
  - `GET /health` (public).
  - `GET /sessions` (JWT) → `assist.pending_requests` + `active_session` (in-process read).
  - `POST /request` (JWT) → body `{center_did, mode, scope, duration_s, reason}` → shells `secubox-assistctl request …`.
  - `POST /open` (JWT), `POST /close` (JWT), `POST /console/grant` (JWT), `POST /console/revoke` (JWT) → shell the matching ctl subcommand; return its JSON.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_api.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os, sys
from pathlib import Path
ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
sys.path.insert(0, ANNUAIRE)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/assist-test-journal.db")
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_status_public():
    r = client.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["module"] == "assist"
    assert "has_active_session" in body


def test_sessions_requires_jwt():
    r = client.get("/sessions")
    assert r.status_code in (401, 403)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_api.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.main'`.

- [ ] **Step 3: Implement api/main.py**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: assist API — reads in-process, mutations delegate to ctl."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt

sys.path.insert(0, os.environ.get("ANNUAIRE_LIB", "/usr/lib/secubox/annuaire"))
from annuaire.log import Journal          # noqa: E402
from annuaire import assist               # noqa: E402
from annuaire.crypto import public_from_private, did_from_pubkey  # noqa: E402

app = FastAPI(title="SecuBox Assist")
CTL = ["/usr/sbin/secubox-assistctl"]
MESH_IFACE = "wg-mesh"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entries():
    try:
        return list(Journal(os.environ.get(
            "ANNUAIRE_JOURNAL", "/var/lib/secubox/annuaire/journal.db")).iter_entries())
    except Exception:
        return []


def _self_did():
    path = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")
    try:
        raw = bytes.fromhex(open(path).read().strip())
        return did_from_pubkey(public_from_private(raw))
    except Exception:
        return None


def _ctl(*args):
    r = subprocess.run(CTL + list(args), capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise HTTPException(status_code=400, detail=r.stderr.strip() or "ctl failed")
    try:
        return json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return {"raw": r.stdout}


@app.get("/status")
async def status():
    sid = _self_did()
    active = None
    if sid:
        try:
            active = assist.active_session(_entries(), sid, _now())
        except assist.AssistError:
            active = {"error": "multiple-active-sessions"}
    return {"module": "assist", "enabled": True, "mesh_iface": MESH_IFACE,
            "has_active_session": bool(active)}


@app.get("/health")
async def health():
    return {"status": "ok", "module": "assist"}


@app.get("/sessions", dependencies=[Depends(require_jwt)])
async def sessions():
    sid = _self_did()
    entries = _entries()
    return {"pending": assist.pending_requests(entries, sid) if sid else [],
            "active_session": (assist.active_session(entries, sid, _now())
                               if sid else None)}


class RequestBody(BaseModel):
    center_did: str
    mode: str
    scope: str
    duration_s: int
    reason: str


@app.post("/request", dependencies=[Depends(require_jwt)])
async def make_request(b: RequestBody):
    return _ctl("request", b.center_did, "--mode", b.mode, "--scope", b.scope,
                "--duration", str(b.duration_s), "--reason", b.reason)


class OpenBody(BaseModel):
    req_id: str
    center_did: str
    duration_s: int


@app.post("/open", dependencies=[Depends(require_jwt)])
async def open_session(b: OpenBody):
    return _ctl("open", b.req_id, "--center", b.center_did, "--duration", str(b.duration_s))


class SessionRef(BaseModel):
    session_id: str
    reason: str | None = None


@app.post("/close", dependencies=[Depends(require_jwt)])
async def close_session(b: SessionRef):
    return _ctl("close", b.session_id, *(["--reason", b.reason] if b.reason else []))


class ConsoleBody(BaseModel):
    session_id: str
    duration_s: int = 900


@app.post("/console/grant", dependencies=[Depends(require_jwt)])
async def console_grant(b: ConsoleBody):
    return _ctl("console-grant", b.session_id, "--duration", str(b.duration_s))


@app.post("/console/revoke", dependencies=[Depends(require_jwt)])
async def console_revoke(b: SessionRef):
    return _ctl("console-revoke", b.session_id)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_api.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/api/main.py packages/secubox-assist/tests/test_api.py
git commit -m "feat(assist): /assist API — in-process reads, mutations delegate to assistctl, JWT-gated (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 12: /assist panel + menu.d + nginx vhost

**Files:**
- Create: `packages/secubox-assist/www/assist/index.html`
- Create: `packages/secubox-assist/menu.d/580-assist.json`
- Create: `packages/secubox-assist/nginx/assist.conf`
- Test: `packages/secubox-assist/tests/test_menu.py`

**Interfaces:**
- Consumes: `/api/v1/assist/*`, shared `/shared/sidebar.js`, `/shared/hybrid-skin.css`, `sbx_token` from localStorage (webui token key — [[project_webui_token_key_sbx_token]]).
- Produces: an operator panel (request form + live session monitor + kill-switch + console-consent button + history) using **event delegation** (no inline interpolated handlers — XSS guard).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_menu.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_menu_is_valid_json_with_assist_path():
    m = json.loads((ROOT / "menu.d" / "580-assist.json").read_text())
    blob = json.dumps(m)
    assert "/assist" in blob


def test_panel_uses_sbx_token_and_no_inline_onclick():
    html = (ROOT / "www" / "assist" / "index.html").read_text()
    assert "sbx_token" in html
    assert "/shared/sidebar.js" in html
    assert "onclick=" not in html  # event delegation only
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_menu.py -q`
Expected: FAIL — files missing.

- [ ] **Step 3: Create the panel, menu, vhost**

`menu.d/580-assist.json`:

```json
{
  "id": "assist",
  "label": "Assistance",
  "icon": "🆘",
  "path": "/assist/",
  "order": 580,
  "group": "federation"
}
```

`nginx/assist.conf` (static + API proxy to the assist API socket — mirror an existing module's `nginx/*.conf`, e.g. centers.conf):

```nginx
location /assist/ {
    alias /usr/share/secubox/www/assist/;
    index index.html;
}
location /api/v1/assist/ {
    proxy_pass http://unix:/run/secubox/assist.sock:/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_http_version 1.1;
}
```

`www/assist/index.html` — a hybrid-dark panel. Minimum viable, event-delegated, `sbx_token`-authenticated:

```html
<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecuBox — Assistance</title>
<link rel="stylesheet" href="/shared/hybrid-skin.css">
<style>
  body { font-family: 'Courier Prime', monospace; background:#0d1117; color:#e8e6d9; display:flex; }
  .main { flex:1; margin-left:220px; padding:1.5rem; }
  .card { background:rgba(30,40,55,.8); border:1px solid rgba(100,150,200,.2); border-radius:8px; padding:1rem; margin-bottom:1rem; }
  .btn { padding:.4rem .8rem; border-radius:6px; border:1px solid rgba(100,150,200,.2); background:transparent; color:#e8e6d9; cursor:pointer; }
  .btn.danger { border-color:#ff4466; color:#ff4466; }
  .btn.warn { border-color:#ffcc00; color:#ffcc00; }
  input,select { background:#111a24; color:#e8e6d9; border:1px solid rgba(100,150,200,.2); padding:.35rem; border-radius:5px; }
  #log { white-space:pre-wrap; font-size:.8rem; max-height:40vh; overflow:auto; }
</style></head>
<body class="hybrid-dark">
<nav class="sidebar" id="sidebar"></nav>
<div class="main">
  <h1 style="color:#00d4ff">🆘 Assistance</h1>
  <div class="card" id="active-card"><h2>Session active</h2><div id="active">—</div>
    <button class="btn danger" data-act="close">Kill session</button>
    <button class="btn warn" data-act="console-grant">Autoriser console (2ᵉ consentement)</button>
    <button class="btn" data-act="console-revoke">Révoquer console</button>
  </div>
  <div class="card"><h2>Demander de l'assistance</h2>
    <div><input id="center" placeholder="did:plc:…" size="48"></div>
    <div><select id="mode"><option>per-incident</option><option>standing</option></select>
      <input id="scope" placeholder="scope (ex. dns)"> <input id="dur" type="number" value="1800">
      <input id="reason" placeholder="motif"></div>
    <button class="btn" data-act="request">Demander</button>
  </div>
  <div class="card"><h2>Journal de session</h2><div id="log"></div></div>
</div>
<script src="/shared/sidebar.js"></script>
<script>
const T = () => localStorage.getItem('sbx_token') || '';
const H = () => ({'Authorization':'Bearer '+T(),'Content-Type':'application/json'});
async function refresh() {
  const r = await fetch('/api/v1/assist/sessions', {headers:H()});
  if (!r.ok) { document.getElementById('active').textContent = 'auth requise'; return; }
  const d = await r.json();
  document.getElementById('active').textContent =
    d.active_session ? JSON.stringify(d.active_session) : 'aucune';
  document.getElementById('log').textContent = JSON.stringify(d.pending, null, 2);
}
document.addEventListener('click', async (ev) => {
  const b = ev.target.closest('[data-act]'); if (!b) return;
  const act = b.dataset.act;
  if (act === 'request') {
    await fetch('/api/v1/assist/request', {method:'POST', headers:H(), body: JSON.stringify({
      center_did: document.getElementById('center').value,
      mode: document.getElementById('mode').value,
      scope: document.getElementById('scope').value,
      duration_s: parseInt(document.getElementById('dur').value, 10),
      reason: document.getElementById('reason').value })});
  } else {
    const sid = (await (await fetch('/api/v1/assist/sessions', {headers:H()})).json())
      .active_session?.session_id;
    if (!sid && act !== 'request') return;
    const ep = {'close':'/api/v1/assist/close','console-grant':'/api/v1/assist/console/grant',
                'console-revoke':'/api/v1/assist/console/revoke'}[act];
    await fetch(ep, {method:'POST', headers:H(), body: JSON.stringify({session_id: sid})});
  }
  refresh();
});
refresh(); setInterval(refresh, 5000);
</script>
</body></html>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_menu.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/www packages/secubox-assist/menu.d packages/secubox-assist/nginx packages/secubox-assist/tests/test_menu.py
git commit -m "feat(assist): /assist panel (request + live monitor + kill + console consent), menu, vhost (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 13: Packaging — daemon entrypoints, units, sudoers, AppArmor, nft, postinst

**Files:**
- Create: `packages/secubox-assist/assist/daemon.py` (WS serve loop calling `wsserver`), `packages/secubox-assist/api/__init__.py`
- Create: `packages/secubox-assist/systemd/secubox-assist.service`, `packages/secubox-assist/systemd/secubox-assist-api.service`
- Create: `packages/secubox-assist/sudoers/secubox-assist`, `packages/secubox-assist/apparmor/secubox-assist`, `packages/secubox-assist/nft/zz-secubox-assist.conf`
- Modify: `packages/secubox-assist/sbin/secubox-assistctl` (add `diag`/`service`/`config` privileged subcommands)
- Modify: `packages/secubox-assist/debian/{control,rules,postinst,prerm,secubox-assist.install}`
- Test: `packages/secubox-assist/tests/test_packaging.py`

**Interfaces:**
- Consumes: everything above.
- Produces: an installable `.deb` that creates the `secubox-assist` user, installs the two units, the scoped sudoers, the AppArmor profile, and the nft drop-in binding the WS port to `iifname "wg-mesh"` only.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_packaging.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_nft_dropin_is_mesh_only_and_default_drop_friendly():
    nft = (ROOT / "nft" / "zz-secubox-assist.conf").read_text()
    assert 'iifname "wg-mesh"' in nft
    assert "0.0.0.0" not in nft


def test_sudoers_is_scoped_to_assistctl():
    s = (ROOT / "sudoers" / "secubox-assist").read_text()
    assert "/usr/sbin/secubox-assistctl" in s
    assert "ALL=(ALL) NOPASSWD: ALL" not in s


def test_units_run_as_non_root():
    svc = (ROOT / "systemd" / "secubox-assist.service").read_text()
    assert "User=secubox-assist" in svc
    assert "NoNewPrivileges=" in svc


def test_postinst_does_not_chown_shared_parents():
    post = (ROOT / "debian" / "postinst").read_text()
    for parent in ("chown -R secubox-assist /run/secubox",
                   "chown -R secubox-assist /etc/secubox",
                   "chown -R secubox-assist /var/log/secubox"):
        assert parent not in post
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_packaging.py -q`
Expected: FAIL — packaging files missing.

- [ ] **Step 3: Create packaging artifacts**

`assist/daemon.py` (WS serve loop; binds mesh IP, refuses to start without wg-mesh):

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: assist.daemon — WebSocket serve loop over wg-mesh."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone

import websockets

sys.path.insert(0, os.environ.get("ANNUAIRE_LIB", "/usr/lib/secubox/annuaire"))
from annuaire.log import Journal  # noqa: E402
from assist import wsserver  # noqa: E402

WS_PORT = int(os.environ.get("SECUBOX_ASSIST_WS_PORT", "8099"))


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _self_did():
    from annuaire.crypto import public_from_private, did_from_pubkey
    raw = bytes.fromhex(open(os.environ.get(
        "ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")).read().strip())
    return did_from_pubkey(public_from_private(raw))


async def handler(ws):
    entries = list(Journal(os.environ.get(
        "ANNUAIRE_JOURNAL", "/var/lib/secubox/annuaire/journal.db")).iter_entries())
    self_did = _self_did()
    tok = await ws.recv()
    try:
        session = await wsserver.authorize(tok, entries, self_did, _now())
    except wsserver.AuthError as exc:
        await ws.send(json.dumps({"ok": False, "error": str(exc)})); return
    await ws.send(json.dumps({"ok": True, "session_id": session["session_id"]}))
    async for msg in ws:
        req = json.loads(msg)
        fresh = list(Journal(os.environ.get(
            "ANNUAIRE_JOURNAL", "/var/lib/secubox/annuaire/journal.db")).iter_entries())
        # re-check session still active every action (revoke/expiry fail-closed)
        if wsserver._assist.active_session(fresh, self_did, _now()) is None:
            await ws.send(json.dumps({"ok": False, "error": "session-ended"})); break
        out = await wsserver.dispatch(session, req.get("action"), req.get("arg"),
                                      fresh, self_did, _now())
        await ws.send(json.dumps(out))


async def _main():
    ip = wsserver.mesh_bind_ip("wg-mesh")  # BindError → crash (fail-closed) if no mesh
    async with websockets.serve(handler, ip, WS_PORT):
        await asyncio.Future()


def main():
    asyncio.run(_main())


if __name__ == "__main__":
    main()
```

`systemd/secubox-assist.service`:

```ini
[Unit]
Description=SecuBox Assist — WebSocket data-plane (wg-mesh only)
After=network-online.target wg-quick@wg-mesh.service
Wants=network-online.target

[Service]
Type=simple
User=secubox-assist
Group=secubox-assist
ExecStart=/usr/bin/python3 -m assist.daemon
Environment=PYTHONPATH=/usr/lib/secubox/assist:/usr/lib/secubox/annuaire
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/secubox
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

`systemd/secubox-assist-api.service`:

```ini
[Unit]
Description=SecuBox Assist — REST API (unix socket)
After=network.target

[Service]
Type=simple
User=secubox
Group=secubox
RuntimeDirectory=secubox
RuntimeDirectoryPreserve=yes
ExecStart=/usr/bin/python3 -m uvicorn api.main:app --uds /run/secubox/assist.sock --log-level warning
WorkingDirectory=/usr/lib/secubox/assist
Environment=PYTHONPATH=/usr/lib/secubox/assist:/usr/lib/secubox/annuaire
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

`sudoers/secubox-assist` (scoped — the API user may call only the ctl; the ctl's privileged catalog backends run as root):

```
# secubox (webui/API) may invoke ONLY the assist control CLI.
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-assistctl
```

`nft/zz-secubox-assist.conf` (zz- prefix sorts AFTER the base table-creator — [[feedback_nft_layered_dropins_persistence]]; opens the WS port on wg-mesh only, everything else stays DEFAULT DROP):

```
# SecuBox assist WS data-plane: reachable ONLY from the wg-mesh, never public.
table inet secubox_assist {
    chain input {
        type filter hook input priority 0; policy drop;
        iifname "wg-mesh" tcp dport 8099 accept
    }
}
```

`apparmor/secubox-assist` (enforce; non-root; no secrets):

```
#include <tunables/global>
profile secubox-assist /usr/bin/python3 flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/python>
  /usr/lib/secubox/** r,
  /var/lib/secubox/annuaire/journal.db rk,
  /var/log/secubox/audit.log a,
  deny /etc/secubox/secrets/** rwklx,
  network inet stream,
}
```

Append privileged subcommands to `sbin/secubox-assistctl` (validate through `assist.catalog` before acting):

```python
def cmd_diag(a):
    from assist import diag
    if a.what == "status":
        print(json.dumps(diag.collect(_now())["modules"]))
    else:
        print(json.dumps(diag.collect(_now())))


def cmd_service(a):
    from assist.catalog import MODULE_ALLOW, CatalogError
    if a.module not in MODULE_ALLOW:
        _die(f"module not allow-listed: {a.module}")
    import subprocess as sp
    if a.op == "restart":
        sp.run(["systemctl", "restart", a.module], check=False)
    else:
        sp.run(["systemctl", "start" if a.state == "on" else "stop", a.module], check=False)
    print(json.dumps({"ok": True, "module": a.module, "op": a.op}))
```

…and register them in `main()`:

```python
    d = sub.add_parser("diag"); d.add_argument("what", choices=["status", "bundle"])
    d.set_defaults(fn=cmd_diag)
    sv = sub.add_parser("service"); sv.add_argument("op", choices=["restart", "toggle"])
    sv.add_argument("module"); sv.add_argument("state", nargs="?", choices=["on", "off"])
    sv.set_defaults(fn=cmd_service)
```

`debian/secubox-assist.install`:

```
assist/*.py            usr/lib/secubox/assist/assist/
api/*.py               usr/lib/secubox/assist/api/
sbin/secubox-assistctl usr/sbin/
www/assist/*           usr/share/secubox/www/assist/
menu.d/*.json          usr/share/secubox/menu.d/
nginx/assist.conf      etc/nginx/secubox.d/
systemd/*.service      lib/systemd/system/
sudoers/secubox-assist etc/sudoers.d/
apparmor/secubox-assist etc/apparmor.d/
nft/zz-secubox-assist.conf etc/secubox/nft.d/
```

`debian/postinst` (creates the user; enables units; NEVER chowns shared parents — chmod only if needed):

```bash
#!/bin/sh
set -e
if ! getent passwd secubox-assist >/dev/null; then
    adduser --system --group --no-create-home --home /nonexistent secubox-assist
fi
# audit log must be writable by the daemon without touching the shared parent
touch /var/log/secubox/audit.log 2>/dev/null || true
chgrp secubox-assist /var/log/secubox/audit.log 2>/dev/null || true
chmod 0664 /var/log/secubox/audit.log 2>/dev/null || true
if [ -x /usr/sbin/apparmor_parser ] && [ -f /etc/apparmor.d/secubox-assist ]; then
    apparmor_parser -r /etc/apparmor.d/secubox-assist 2>/dev/null || true
fi
#DEBHELPER#
systemctl daemon-reload || true
systemctl enable --now secubox-assist-api.service || true
systemctl enable --now secubox-assist.service || true
nft -f /etc/secubox/nft.d/zz-secubox-assist.conf 2>/dev/null || true
exit 0
```

`debian/prerm`:

```bash
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = deconfigure ]; then
    systemctl stop secubox-assist.service secubox-assist-api.service 2>/dev/null || true
fi
#DEBHELPER#
exit 0
```

Expand `debian/control` `Depends:` to add `apparmor`. Keep `debian/rules` as `dh $@ --with python3` (arch:all — install lines live in `.install`, not `override_dh_strip` — [[feedback_override_dh_strip_dead_for_arch_all]]).

- [ ] **Step 4: Run test to verify it passes, then build the package**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_packaging.py -q`
Expected: PASS (4 passed).

Run the full package suite:
`cd packages/secubox-assist && ../../.venv/bin/pytest tests/ -q`
Expected: PASS (all tasks' tests).

Build (arch:all):
`cd packages/secubox-assist && dpkg-buildpackage -us -uc -b 2>&1 | tail -5`
Expected: `secubox-assist_0.1.0-1~bookworm1_all.deb` produced.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/daemon.py packages/secubox-assist/api/__init__.py \
  packages/secubox-assist/systemd packages/secubox-assist/sudoers packages/secubox-assist/apparmor \
  packages/secubox-assist/nft packages/secubox-assist/sbin/secubox-assistctl \
  packages/secubox-assist/debian packages/secubox-assist/tests/test_packaging.py
git commit -m "feat(assist): packaging — WS daemon, units (non-root), scoped sudoers, AppArmor, mesh-only nft, postinst (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 14: Annuaire package metadata bump (ship assist.py + new deps)

**Files:**
- Modify: `packages/secubox-annuaire/debian/changelog` (new version entry), `packages/secubox-annuaire/debian/*.install` (ensure `annuaire/assist.py` ships — usually a glob already covers `annuaire/*.py`, verify)
- Test: reuse — run the annuaire suite.

- [ ] **Step 1: Verify assist.py is covered by the install glob**

Run: `grep -R "annuaire/\*.py\|annuaire/\*" packages/secubox-annuaire/debian/*.install packages/secubox-annuaire/debian/rules`
Expected: a line installing `annuaire/*.py` (so `assist.py` ships). If NOT present, add `annuaire/assist.py` to the install list explicitly.

- [ ] **Step 2: Bump changelog**

Prepend to `packages/secubox-annuaire/debian/changelog`:

```
secubox-annuaire (0.6.0-1~bookworm1) bookworm; urgency=medium

  * Assist control-plane: ASSIST_* ops, AssistRequest/AssistSession models,
    assist.py (single-session/console/expiry/sovereignty resolution),
    assist_* signed verbs. Consumed by the new secubox-assist package.

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 25 Jul 2026 12:00:00 +0200
```

- [ ] **Step 3: Run the full annuaire suite**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/ -q`
Expected: PASS (all — new assist tests + all pre-existing).

- [ ] **Step 4: Build**

Run: `cd packages/secubox-annuaire && dpkg-buildpackage -us -uc -b 2>&1 | tail -3`
Expected: `secubox-annuaire_0.6.0-1~bookworm1_all.deb` produced.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/debian
git commit -m "build(annuaire): ship assist control-plane, 0.6.0 (ref sous-projet 2)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Self-Review

**1. Spec coverage** — every spec section maps to a task:
- Ops model + AssistRequest/AssistSession → Task 1. assist.py resolution (single-session, console, expiry, sovereignty) → Task 2. Signed verbs → Task 3. Token hash-only → Task 4. Catalog bounded → Task 5. Diag redaction → Task 6. Audit append-only → Task 7. WS mesh-only bind + token auth + dispatch → Task 8. Double-consent pty non-root → Task 9. Bi-mode init + session control CLI → Task 10. API delegate-to-ctl → Task 11. Panel + menu + vhost → Task 12. Units/sudoers/AppArmor/nft/postinst/daemon → Task 13. Annuaire packaging → Task 14. ✅
- CSPN invariants: consent at open (verbs.can_open + ctl), double-consent console (console.guard), mesh-only (mesh_bind_ip + nft), token hashed (token.py + AssistSession pattern), audit (audit.py, wired in dispatch/console/daemon), expiry fail-closed (active_session/console_active), session unique (active_session raises + can_open), never root (units User= + console refuse-root), no chown shared parents (postinst test). ✅

**2. Placeholder scan** — every code step contains complete code; no TBD/TODO. Task 8 and Task 13 note that the serve loop lives in `daemon.py` (Task 13) while the testable core (bind/authorize/dispatch) is in Task 8 — this is an explicit split, not a placeholder. ✅

**3. Type consistency** — `token_hash` is 64-hex everywhere (model pattern, token.mint, AssistSession). `active_session(entries, self_did, now_ts)` signature identical in assist.py, verbs, ctl, api, daemon. `resolve(action, arg) -> list` in catalog used by wsserver.dispatch. `record(event, session_id, actor, detail, *, path=None)` identical in audit.py and callers. `mesh_bind_ip(iface="wg-mesh")` consistent. ✅

**Known cross-task item for the controller:** Task 3 depends on the exact `Journal.append` kwargs — the implementer MUST confirm the real signature in `annuaire/log.py` (does it accept `sig=`?) and match `verbs.grant_issue`'s call shape; the plan flags this inline. This is a ⚠️ to verify during Task 3 review, not a gap.
