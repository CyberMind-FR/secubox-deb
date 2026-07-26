# Assist OFFER↔REQUEST Dual + Multi-Layer Join Link — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the shipped `secubox-assist` socle with a decentralized OFFER↔REQUEST marketplace (mutual double-accept rendezvous → existing SESSION_OPEN) and a multi-layer auto-escalating join link (public URL → ephemeral mesh identity → ephemeral WireGuard peer → session on that tunnel) for total reach, preserving the WG-only session data-plane.

**Architecture:** Phase A is pure control-plane on the annuaire journal (new `ASSIST_OFFER/OFFER_REVOKE/REQUEST_OPEN/MATCH_ACCEPT` ops + a pure decentralized matcher) plus a thin rendezvous orchestrator that, on `match_ready`, drives the *existing* `assist_session_open` on the requester side. Phase B adds a single-use join-link and a layered bootstrap (`joinlink.py`, `escalate.py`) that stands up an ephemeral identity + ephemeral WG peer (`10.11.0.0/24`) so a non-enrolled party can join a session over WireGuard; the public URL is only the bootstrap. Everything reuses the socle's catalog/console/audit/token/consent unchanged.

**Tech Stack:** Python 3.11, Ed25519 (`annuaire.crypto`), BLAKE2b, FastAPI/uvicorn (API), WireGuard via `secubox-p2p`, nftables, pytest.

## Global Constraints

- **SPDX header** (verbatim) on every new Python/Bash file:
  ```
  # SPDX-License-Identifier: LicenseRef-CMSD-1.0
  # Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  # Source-Disclosed License — All rights reserved except as expressly granted.
  # See LICENCE-CMSD-1.0.md for terms.
  ```
- **Data-plane WG-only**: the assist session WS binds `wg-mesh` OR `wg-ephemeral` (`10.11.0.0/24`) only — NEVER `0.0.0.0`. The public join-link URL is the ONLY public surface and is bounded to the token redeem (no session endpoint is ever public). nft opens the WS port only on `iifname "wg-mesh"`/`"wg-ephemeral"`.
- **Sovereignty**: a match/offer/request from a peer never opens anything — only the requester box's own signed `assist_session_open` (with operator consent) opens a session. All resolvers pass `self_did` and filter `issued_by == self_did` where authority is involved.
- **Ephemeral identity/peer/token**: session-scoped, `ephemeral=true`, hard-cap TTL, auto-revoked at teardown; NEVER promoted to a persistent gondwana member. Join-link single-use + time-boxed; only its BLAKE2b hash is journaled.
- **Consent unchanged**: the existing `SESSION_OPEN` operator consent, double-consent console, bounded catalog (auth/secrets unreachable), token-hash, append-only audit, fail-closed expiry all still apply on top.
- **No privileged action in-process**: API mutations shell out to `secubox-assistctl`; never chown shared parents (`/run/secubox`, `/etc/secubox`, `/var/log/secubox`, `/var/lib/secubox`).
- Commit messages end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO AI/Claude references. Versioning `X.Y.Z-1~bookworm1`; `#DEBHELPER#` alone on its line.
- Tests run with the repo `.venv`, per-directory (`cd packages/<pkg> && ../../.venv/bin/pytest tests/…`).

## Socle reference (shipped — reuse, do not reinvent)

- `annuaire/model.py`: `class Op(str, Enum)` (add members after `ASSIST_CONSOLE_REVOKE`), `now_rfc3339()`, `ASSIST_MODES`, DID pattern `^did:plc:[0-9a-f]{32}$`, scope pattern `^[a-z0-9][a-z0-9._-]*$`. Existing models `AssistRequest`/`AssistSession`.
- `annuaire/assist.py`: `_by(entries, op)`, `active_session(entries, self_did, now_ts)`, `console_active`, `pending_requests`, `can_open`, `class AssistError`. Reuse `_by`, `grants._op`/`grants._payload`.
- `annuaire/verbs.py`: `_assist_append(journal, priv, op, model_obj, payload_type)` (model_dump excl sig/signer_did → sign `canonical_bytes(payload)` → `journal.append(op, payload_type, payload, author, sig, author_pubkey_hex=)`). `assist_request/accept/session_open/session_close/console_grant/console_revoke`.
- `annuaire/crypto.py`: `sign(priv,msg)->hex`, `verify(pub_hex,msg,sig)->bool`, `canonical_bytes(dict)->bytes`, `public_from_private`, `did_from_pubkey`.
- `secubox-assist/assist/`: `token.mint()->(tok,hash)`, `token.hash_token`, `token.verify_token`, `audit.record(event,session_id,actor,detail,*,path=None)`, `wsserver.mesh_bind_ip(iface)`, `wsserver.authorize(tok,entries,self_did,now_ts)`, `wsserver.dispatch(...)`, `catalog.resolve`, `console.guard/ConsoleSession`, `daemon.py`. `sbin/secubox-assistctl` (session control), `api/main.py`. Package has `conftest.py` + `pytest.ini` (`asyncio_mode=auto`, `pythonpath=../secubox-annuaire`).
- `secubox-p2p`: `wg-mesh` WireGuard, `sbx-mesh-invite`/`join`, `adopt_state`. Basis for the ephemeral WG peer.

## File Structure

**Phase A — control-plane (`packages/secubox-annuaire/`):**
- `annuaire/model.py` — +4 Op members, +3 models (`AssistOffer`, `AssistOpenRequest`, `AssistMatchAccept`).
- `annuaire/assist_match.py` (new) — pure matcher.
- `annuaire/verbs.py` — +4 verbs.
- `tests/test_assist_match_model.py`, `tests/test_assist_match.py`, `tests/test_assist_match_verbs.py`.

**Phase A — rendezvous (`packages/secubox-assist/`):**
- `assist/rendezvous.py` (new) — on `match_ready`, drive requester-side `assist_session_open` via ctl.
- `tests/test_rendezvous.py`.

**Phase B — multi-layer link (`packages/secubox-assist/`):**
- `assist/joinlink.py` (new) — mint/redeem single-use join-link.
- `assist/escalate.py` (new) — layered ephemeral identity + WG peer + teardown.
- `tests/test_joinlink.py`, `tests/test_escalate.py`.

**Surface + packaging:**
- `sbin/secubox-assistctl` (extend), `api/main.py` (extend), `www/assist/index.html` (tabs), `nft/secubox-assist.nft` (add `wg-ephemeral`), `debian/{changelog,control,rules}`, p2p ephemeral range.
- `tests/test_assistctl_dual.py`, `tests/test_api_dual.py`, `tests/test_packaging_dual.py`.

---

## Task 1: annuaire model — offer/request/match ops + models

**Files:**
- Modify: `packages/secubox-annuaire/annuaire/model.py`
- Test: `packages/secubox-annuaire/tests/test_assist_match_model.py`

**Interfaces — Produces:**
- `Op.ASSIST_OFFER="assist_offer"`, `Op.ASSIST_OFFER_REVOKE="assist_offer_revoke"`, `Op.ASSIST_REQUEST_OPEN="assist_request_open"`, `Op.ASSIST_MATCH_ACCEPT="assist_match_accept"`.
- `AssistOffer(offer_id:str, tags:list[str], scope:Optional[str], ttl_s:int[60..86400], issued_by:str[DID], created_at:str, sig, signer_did)`.
- `AssistOpenRequest(req_id:str, tags:list[str], scope:Optional[str], ttl_s:int, reason:str[1..512], issued_by:str[DID], created_at, sig, signer_did)`.
- `AssistMatchAccept(match_id:str[64hex], offer_id:str, req_id:str, side:str["offer"|"request"], issued_by:str[DID], created_at, sig, signer_did)`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_assist_match_model.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from pydantic import ValidationError
from annuaire.model import (Op, AssistOffer, AssistOpenRequest, AssistMatchAccept)

DID = "did:plc:" + "a" * 32


def test_ops_present():
    assert Op.ASSIST_OFFER == "assist_offer"
    assert Op.ASSIST_REQUEST_OPEN == "assist_request_open"
    assert Op.ASSIST_MATCH_ACCEPT == "assist_match_accept"


def test_offer_valid_and_extra_forbidden():
    o = AssistOffer(offer_id="o1", tags=["lora", "meshtastic"], scope=None,
                    ttl_s=1800, issued_by=DID)
    assert o.tags == ["lora", "meshtastic"] and o.sig is None
    with pytest.raises(ValidationError):
        AssistOffer(offer_id="o1", tags=["x"], scope=None, ttl_s=1800,
                    issued_by=DID, sneaky=True)


def test_open_request_reason_bounds():
    AssistOpenRequest(req_id="r1", tags=["lora"], scope="dns", ttl_s=600,
                      reason="need help", issued_by=DID)
    with pytest.raises(ValidationError):
        AssistOpenRequest(req_id="r1", tags=["lora"], scope="dns", ttl_s=600,
                          reason="", issued_by=DID)


def test_match_accept_side_and_hexid():
    AssistMatchAccept(match_id="b" * 64, offer_id="o1", req_id="r1",
                      side="offer", issued_by=DID)
    with pytest.raises(ValidationError):
        AssistMatchAccept(match_id="short", offer_id="o1", req_id="r1",
                          side="offer", issued_by=DID)
    with pytest.raises(ValidationError):
        AssistMatchAccept(match_id="b" * 64, offer_id="o1", req_id="r1",
                          side="bogus", issued_by=DID)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_match_model.py -q`
Expected: FAIL — `ImportError: cannot import name 'AssistOffer'`.

- [ ] **Step 3: Implement**

In `annuaire/model.py`, add to `class Op` after `ASSIST_CONSOLE_REVOKE`:

```python
    # Assist marketplace (dual offer/request rendezvous)
    ASSIST_OFFER          = "assist_offer"          # advertise availability to help
    ASSIST_OFFER_REVOKE   = "assist_offer_revoke"
    ASSIST_REQUEST_OPEN   = "assist_request_open"   # open (untargeted) request for help
    ASSIST_MATCH_ACCEPT   = "assist_match_accept"   # one side accepts a proposed match
```

After the existing `AssistSession` model, add:

```python
ASSIST_MATCH_SIDES = {"offer", "request"}


class AssistOffer(BaseModel):
    """A signed advertisement of availability to help (marketplace OFFER)."""
    model_config = ConfigDict(extra="forbid")
    offer_id:   str = Field(..., description="stable id for this offer")
    tags:       list[str] = Field(..., min_length=1, description="free-form capability tags")
    scope:      Optional[str] = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    ttl_s:      int = Field(..., ge=60, le=86400)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None


class AssistOpenRequest(BaseModel):
    """A signed open (untargeted) request for help (marketplace REQUEST)."""
    model_config = ConfigDict(extra="forbid")
    req_id:     str = Field(..., description="stable id for this open request")
    tags:       list[str] = Field(..., min_length=1)
    scope:      Optional[str] = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    ttl_s:      int = Field(..., ge=60, le=86400)
    reason:     str = Field(..., min_length=1, max_length=512)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None


class AssistMatchAccept(BaseModel):
    """One side's signed acceptance of a proposed offer↔request match."""
    model_config = ConfigDict(extra="forbid")
    match_id:   str = Field(..., pattern=r"^[0-9a-f]{64}$")
    offer_id:   str = Field(...)
    req_id:     str = Field(...)
    side:       str = Field(..., description="'offer' or 'request'")
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None

    @field_validator("side")
    @classmethod
    def _side_known(cls, v: str) -> str:
        if v not in ASSIST_MATCH_SIDES:
            raise ValueError(f"side must be one of {sorted(ASSIST_MATCH_SIDES)}")
        return v
```

Ensure `field_validator` and `Optional` are imported (they are — reuse).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_match_model.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/model.py packages/secubox-annuaire/tests/test_assist_match_model.py
git commit -m "feat(annuaire): assist marketplace ops + Offer/OpenRequest/MatchAccept models (ref assist-dual)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 2: annuaire assist_match.py — pure decentralized matcher

**Files:**
- Create: `packages/secubox-annuaire/annuaire/assist_match.py`
- Test: `packages/secubox-annuaire/tests/test_assist_match.py`

**Interfaces:**
- Consumes: `annuaire.assist._by` (op iterator over dicts/LogEntry), `annuaire.grants._payload`, `annuaire.model.Op`, `hashlib`.
- Produces:
  - `match_id(offer_id, req_id) -> str` — `blake2b((offer_id+"|"+req_id).encode(), digest_size=32).hexdigest()` (deterministic, identical on every node).
  - `active_offers(entries, now_ts) -> list[dict]` — OFFER payloads not revoked and `now_ts < created_at + ttl_s` (RFC3339 arithmetic via `_expires_at`).
  - `active_open_requests(entries, now_ts) -> list[dict]`.
  - `matches(entries, now_ts) -> list[tuple[dict, dict, str]]` — `(offer, request, match_id)` for every active pair whose tags intersect AND (scope is None on either OR equal).
  - `match_ready(entries, match_id, now_ts) -> bool` — an `ASSIST_MATCH_ACCEPT{side="offer"}` AND a `{side="request"}` for `match_id` exist, and the underlying offer+request are still active.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_assist_match.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from annuaire.model import Op
from annuaire import assist_match as m

A = "did:plc:" + "1" * 32
B = "did:plc:" + "2" * 32


def e(op, **p):
    return {"op": op.value, "payload": p}


def _offer(oid, tags, by=A, ttl=3600, scope=None, at="2026-07-25T10:00:00Z"):
    return e(Op.ASSIST_OFFER, offer_id=oid, tags=tags, scope=scope, ttl_s=ttl,
             issued_by=by, created_at=at)


def _req(rid, tags, by=B, ttl=3600, scope=None, at="2026-07-25T10:00:00Z"):
    return e(Op.ASSIST_REQUEST_OPEN, req_id=rid, tags=tags, scope=scope, ttl_s=ttl,
             reason="x", issued_by=by, created_at=at)


def test_match_id_deterministic():
    assert m.match_id("o1", "r1") == m.match_id("o1", "r1")
    assert len(m.match_id("o1", "r1")) == 64


def test_tag_intersection_matches():
    entries = [_offer("o1", ["lora", "meshtastic"]), _req("r1", ["lora"])]
    ms = m.matches(entries, now_ts="2026-07-25T10:30:00Z")
    assert len(ms) == 1 and ms[0][2] == m.match_id("o1", "r1")


def test_no_tag_overlap_no_match():
    entries = [_offer("o1", ["lora"]), _req("r1", ["dns"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_scope_must_agree_when_both_set():
    entries = [_offer("o1", ["lora"], scope="dns"), _req("r1", ["lora"], scope="firewall")]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
    entries2 = [_offer("o2", ["lora"], scope="dns"), _req("r2", ["lora"], scope="dns")]
    assert len(m.matches(entries2, now_ts="2026-07-25T10:30:00Z")) == 1


def test_expiry_fail_closed():
    entries = [_offer("o1", ["lora"], ttl=60), _req("r1", ["lora"], ttl=60)]
    # created 10:00:00, ttl 60s → expires 10:01:00; at 10:30 both stale
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_revoke_drops_offer():
    entries = [_offer("o1", ["lora"]), _req("r1", ["lora"]),
               e(Op.ASSIST_OFFER_REVOKE, offer_id="o1", issued_by=A)]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_match_ready_needs_both_sides():
    mid = m.match_id("o1", "r1")
    base = [_offer("o1", ["lora"]), _req("r1", ["lora"])]
    only_offer = base + [e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1",
                           req_id="r1", side="offer", issued_by=A)]
    assert not m.match_ready(only_offer, mid, now_ts="2026-07-25T10:30:00Z")
    both = only_offer + [e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1",
                           req_id="r1", side="request", issued_by=B)]
    assert m.match_ready(both, mid, now_ts="2026-07-25T10:30:00Z")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_match.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'annuaire.assist_match'`.

- [ ] **Step 3: Implement `annuaire/assist_match.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire.assist_match — pure, decentralized offer↔request matcher.

Every node computes matches identically from its own journal copy (no
coordinator). match_id is a deterministic BLAKE2b of (offer_id|req_id) so both
sides derive the same id. Expiry is fail-closed (offer/request stale past
created_at+ttl_s). A match is 'ready' only when BOTH sides have posted a signed
ASSIST_MATCH_ACCEPT and the underlying offer+request are still active.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, List, Mapping, Tuple

from .assist import _by  # dict/LogEntry-tolerant op iterator (yields payloads)
from .model import Op


def match_id(offer_id: str, req_id: str) -> str:
    return hashlib.blake2b(f"{offer_id}|{req_id}".encode("utf-8"),
                           digest_size=32).hexdigest()


def _expired(created_at: str, ttl_s: int, now_ts: str) -> bool:
    try:
        c = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        n = datetime.strptime(now_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return True  # unparseable → fail-closed
    return n >= c + timedelta(seconds=int(ttl_s))


def active_offers(entries: List[Mapping[str, Any]], now_ts: str) -> List[dict]:
    revoked = {p.get("offer_id") for p in _by(entries, Op.ASSIST_OFFER_REVOKE)}
    out = []
    for p in _by(entries, Op.ASSIST_OFFER):
        if p.get("offer_id") in revoked:
            continue
        if _expired(p.get("created_at", ""), p.get("ttl_s", 0), now_ts):
            continue
        out.append(p)
    return out


def active_open_requests(entries: List[Mapping[str, Any]], now_ts: str) -> List[dict]:
    out = []
    for p in _by(entries, Op.ASSIST_REQUEST_OPEN):
        if _expired(p.get("created_at", ""), p.get("ttl_s", 0), now_ts):
            continue
        out.append(p)
    return out


def _compatible(offer: dict, request: dict) -> bool:
    if not (set(offer.get("tags", [])) & set(request.get("tags", []))):
        return False
    os_, rs = offer.get("scope"), request.get("scope")
    if os_ and rs and os_ != rs:
        return False
    return True


def matches(entries: List[Mapping[str, Any]], now_ts: str
            ) -> List[Tuple[dict, dict, str]]:
    offers = active_offers(entries, now_ts)
    requests = active_open_requests(entries, now_ts)
    out = []
    for o in offers:
        for r in requests:
            if _compatible(o, r):
                out.append((o, r, match_id(o["offer_id"], r["req_id"])))
    return out


def match_ready(entries: List[Mapping[str, Any]], mid: str, now_ts: str) -> bool:
    accepts = [p for p in _by(entries, Op.ASSIST_MATCH_ACCEPT)
               if p.get("match_id") == mid]
    sides = {p.get("side") for p in accepts}
    if not {"offer", "request"} <= sides:
        return False
    # underlying offer+request must still be active
    live_mids = {mid_ for _, _, mid_ in matches(entries, now_ts)}
    return mid in live_mids
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_match.py -q`
Expected: PASS (7 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/assist_match.py packages/secubox-annuaire/tests/test_assist_match.py
git commit -m "feat(annuaire): assist_match.py — pure decentralized offer/request matcher (ref assist-dual)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 3: annuaire verbs — signed offer/request/match ops

**Files:**
- Modify: `packages/secubox-annuaire/annuaire/verbs.py`
- Test: `packages/secubox-annuaire/tests/test_assist_match_verbs.py`

**Interfaces:**
- Consumes: `_assist_append`, `AssistOffer/AssistOpenRequest/AssistMatchAccept`, `assist_match.match_id`, `did_from_pubkey`, `public_from_private`.
- Produces (each returns the appended `LogEntry`, signed with the caller's key):
  - `assist_offer(journal, priv, tags, scope, ttl_s, offer_id) -> LogEntry`
  - `assist_offer_revoke(journal, priv, offer_id) -> LogEntry`
  - `assist_open_request(journal, priv, tags, scope, ttl_s, reason, req_id) -> LogEntry`
  - `assist_match_accept(journal, priv, offer_id, req_id, side) -> LogEntry` (computes `match_id` internally)

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_assist_match_verbs.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
from annuaire.log import Journal
from annuaire.crypto import canonical_bytes, verify, public_from_private, did_from_pubkey
from annuaire import verbs, assist_match as m
from annuaire.model import Op


def _key():
    p = os.urandom(32)
    return p, did_from_pubkey(public_from_private(p))


def test_offer_signed_and_appended(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    priv, did = _key()
    entry = verbs.assist_offer(j, priv, ["lora"], None, 1800, offer_id="o1")
    assert entry.op == Op.ASSIST_OFFER.value
    assert verify(public_from_private(priv).hex(), canonical_bytes(entry.payload), entry.sig)


def test_full_match_ready(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    ap, ad = _key(); bp, bd = _key()
    verbs.assist_offer(j, ap, ["lora"], None, 3600, offer_id="o1")
    verbs.assist_open_request(j, bp, ["lora"], None, 3600, "help", req_id="r1")
    verbs.assist_match_accept(j, ap, "o1", "r1", "offer")
    verbs.assist_match_accept(j, bp, "o1", "r1", "request")
    entries = list(j.iter_entries())
    assert m.match_ready(entries, m.match_id("o1", "r1"), now_ts="2026-07-25T10:00:00Z")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_match_verbs.py -q`
Expected: FAIL — `AttributeError: module 'annuaire.verbs' has no attribute 'assist_offer'`.

- [ ] **Step 3: Implement** (append to `annuaire/verbs.py`; add imports `from .model import AssistOffer, AssistOpenRequest, AssistMatchAccept` and `from . import assist_match`)

```python
# --- Assist marketplace (dual offer/request) ------------------------------

def assist_offer(journal, priv, tags, scope, ttl_s, offer_id):
    did = did_from_pubkey(public_from_private(priv))
    m_ = AssistOffer(offer_id=offer_id, tags=list(tags), scope=scope,
                     ttl_s=ttl_s, issued_by=did)
    return _assist_append(journal, priv, Op.ASSIST_OFFER, m_, "AssistOffer")


def assist_offer_revoke(journal, priv, offer_id):
    did = did_from_pubkey(public_from_private(priv))
    payload = {"offer_id": offer_id, "issued_by": did, "created_at": now_rfc3339()}
    sig = sign(priv, canonical_bytes(payload))
    return journal.append(op=Op.ASSIST_OFFER_REVOKE, payload=payload,
                          payload_type="AssistOfferRevoke", author=did,
                          author_pubkey_hex=public_from_private(priv).hex(), sig=sig)


def assist_open_request(journal, priv, tags, scope, ttl_s, reason, req_id):
    did = did_from_pubkey(public_from_private(priv))
    m_ = AssistOpenRequest(req_id=req_id, tags=list(tags), scope=scope,
                           ttl_s=ttl_s, reason=reason, issued_by=did)
    return _assist_append(journal, priv, Op.ASSIST_REQUEST_OPEN, m_, "AssistOpenRequest")


def assist_match_accept(journal, priv, offer_id, req_id, side):
    did = did_from_pubkey(public_from_private(priv))
    mid = assist_match.match_id(offer_id, req_id)
    m_ = AssistMatchAccept(match_id=mid, offer_id=offer_id, req_id=req_id,
                           side=side, issued_by=did)
    return _assist_append(journal, priv, Op.ASSIST_MATCH_ACCEPT, m_, "AssistMatchAccept")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_assist_match_verbs.py tests/test_assist_match.py tests/test_assist_match_model.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/verbs.py packages/secubox-annuaire/tests/test_assist_match_verbs.py
git commit -m "feat(annuaire): assist_offer/open_request/match_accept signed verbs (ref assist-dual)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 4: rendezvous.py — match_ready → requester-side SESSION_OPEN

**Files:**
- Create: `packages/secubox-assist/assist/rendezvous.py`
- Test: `packages/secubox-assist/tests/test_rendezvous.py`

**Interfaces:**
- Consumes: `annuaire.assist_match.matches/match_ready/match_id`, `annuaire.assist.active_session`.
- Produces:
  - `ready_matches(entries, self_did, now_ts) -> list[dict]` — for this node, the ready matches where THIS node is the requester (`request.issued_by == self_did`), each `{match_id, offer_id, req_id, offerer_did}`. Sovereignty: only this node's own open requests.
  - `should_open(entries, self_did, now_ts) -> Optional[dict]` — the first ready match this node should open a session for (requester side), or None if a session is already active (single-session invariant) or none ready.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_rendezvous.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "secubox-annuaire"))
from annuaire.model import Op
from annuaire import assist_match as m
from assist import rendezvous as rz

A = "did:plc:" + "1" * 32   # offerer
B = "did:plc:" + "2" * 32   # requester (this node)


def e(op, **p):
    return {"op": op.value, "payload": p}


def _ready_pair(now="2026-07-25T10:00:00Z"):
    mid = m.match_id("o1", "r1")
    return [
        e(Op.ASSIST_OFFER, offer_id="o1", tags=["lora"], scope=None, ttl_s=3600,
          issued_by=A, created_at=now),
        e(Op.ASSIST_REQUEST_OPEN, req_id="r1", tags=["lora"], scope=None, ttl_s=3600,
          reason="x", issued_by=B, created_at=now),
        e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1", req_id="r1",
          side="offer", issued_by=A),
        e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1", req_id="r1",
          side="request", issued_by=B),
    ]


def test_should_open_for_requester():
    r = rz.should_open(_ready_pair(), self_did=B, now_ts="2026-07-25T10:10:00Z")
    assert r and r["offerer_did"] == A and r["req_id"] == "r1"


def test_sovereignty_offerer_does_not_open():
    # node A is the offerer, not the requester → A must NOT open a session
    assert rz.should_open(_ready_pair(), self_did=A, now_ts="2026-07-25T10:10:00Z") is None


def test_no_open_when_session_active():
    entries = _ready_pair() + [e(Op.ASSIST_SESSION_OPEN, session_id="s9", req_id="rX",
                                 center_did=A, issued_by=B, token_hash="a" * 64,
                                 expires_ts="2999-01-01T00:00:00Z")]
    assert rz.should_open(entries, self_did=B, now_ts="2026-07-25T10:10:00Z") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_rendezvous.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist.rendezvous'`.

- [ ] **Step 3: Implement `assist/rendezvous.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.rendezvous — turn a ready match into a session on the
REQUESTER side. Sovereignty: this node only ever opens a session for ITS OWN
open request (request.issued_by == self_did); a match never opens anything on
its own — the caller (ctl) still runs the operator-consented assist_session_open
with center_did = the offerer. Single active session invariant preserved.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional

try:
    from annuaire import assist_match as _mm
    from annuaire import assist as _assist
except Exception:  # pragma: no cover — import shim for isolated tests
    _mm = _assist = None


def ready_matches(entries: List[Mapping[str, Any]], self_did: str,
                  now_ts: str) -> List[dict]:
    if _mm is None:
        return []
    out = []
    for offer, request, mid in _mm.matches(entries, now_ts):
        if request.get("issued_by") != self_did:
            continue  # sovereignty: only our own open requests
        if _mm.match_ready(entries, mid, now_ts):
            out.append({"match_id": mid, "offer_id": offer["offer_id"],
                        "req_id": request["req_id"], "offerer_did": offer["issued_by"]})
    return out


def should_open(entries: List[Mapping[str, Any]], self_did: str,
                now_ts: str) -> Optional[dict]:
    if _assist is not None and _assist.active_session(entries, self_did, now_ts) is not None:
        return None  # single-session invariant
    rm = ready_matches(entries, self_did, now_ts)
    return rm[0] if rm else None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_rendezvous.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/rendezvous.py packages/secubox-assist/tests/test_rendezvous.py
git commit -m "feat(assist): rendezvous.py — ready-match → requester-side session (sovereign) (ref assist-dual)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 5: joinlink.py — single-use time-boxed join link

**Files:**
- Create: `packages/secubox-assist/assist/joinlink.py`
- Test: `packages/secubox-assist/tests/test_joinlink.py`

**Interfaces:**
- Consumes: `assist.token.mint/hash_token/verify_token`, `hashlib`, `json`, `time` via injected `now`.
- Produces:
  - `mint_join(ref: str, ttl_s: int, base_url: str) -> dict` — returns `{"url", "token", "token_hash", "ref", "expires_at"}`; `url = f"{base_url}/assist/join/{token}"`; only `token_hash` is meant to be journaled, `token` goes in the URL only.
  - `verify_join(token: str, token_hash: str) -> bool` — constant-time (`token.verify_token`).
  - `is_expired(expires_at: str, now_ts: str) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_joinlink.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from assist import joinlink as jl


def test_mint_join_shape_and_hash_only():
    j = jl.mint_join(ref="match:abc", ttl_s=900, base_url="https://assist.gk2.example")
    assert j["url"].startswith("https://assist.gk2.example/assist/join/")
    assert j["url"].endswith(j["token"])
    assert len(j["token_hash"]) == 64
    # the URL carries the secret; the hash is what you journal — and they differ
    assert j["token"] not in j["token_hash"]
    assert jl.verify_join(j["token"], j["token_hash"])
    assert not jl.verify_join("bogus", j["token_hash"])


def test_expiry():
    assert jl.is_expired("2026-07-25T10:00:00Z", now_ts="2026-07-25T11:00:00Z")
    assert not jl.is_expired("2026-07-25T12:00:00Z", now_ts="2026-07-25T11:00:00Z")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_joinlink.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist.joinlink'`.

- [ ] **Step 3: Implement `assist/joinlink.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.joinlink — single-use, time-boxed join link. The token
secret travels ONLY in the shared URL; only its BLAKE2b hash is journaled
(same discipline as the session token). Redeem is single-use + expiry-checked
by the caller (escalate.py / ctl).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import token as _token


def _now_plus(ttl_s: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=int(ttl_s))
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def mint_join(ref: str, ttl_s: int, base_url: str) -> dict:
    tok, tok_hash = _token.mint()
    return {"url": f"{base_url.rstrip('/')}/assist/join/{tok}", "token": tok,
            "token_hash": tok_hash, "ref": ref, "expires_at": _now_plus(ttl_s)}


def verify_join(tok: str, token_hash: str) -> bool:
    return _token.verify_token(tok, token_hash)


def is_expired(expires_at: str, now_ts: str) -> bool:
    return str(now_ts) >= str(expires_at)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_joinlink.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/joinlink.py packages/secubox-assist/tests/test_joinlink.py
git commit -m "feat(assist): joinlink.py — single-use time-boxed join link (hash-only journaled) (ref assist-dual)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 6: escalate.py — ephemeral identity + WG peer + teardown (layered)

**Files:**
- Create: `packages/secubox-assist/assist/escalate.py`
- Test: `packages/secubox-assist/tests/test_escalate.py`

**Interfaces:**
- Consumes: `os`, `subprocess` (to `secubox-p2p` for the WG peer), `secrets`.
- Produces:
  - `EPHEMERAL_RANGE = "10.11.0.0/24"`, `EPHEMERAL_IFACE = "wg-ephemeral"`.
  - `class EscalateError(Exception)`.
  - `mint_ephemeral_identity() -> dict` — `{"did", "priv_hex", "ephemeral": True, "created_at"}`; a throwaway Ed25519 key + DID; NEVER written to the persistent member store.
  - `add_ephemeral_peer(pubkey: str, endpoint: str, ip: str) -> list[str]` — returns the argv (list, `shell=False`) that `secubox-p2p` would run to add a session-scoped WG peer in `10.11.0.0/24`; caller execs it. Refuses an ip outside `EPHEMERAL_RANGE` (`EscalateError`).
  - `teardown(ip: str, did: str) -> list[list[str]]` — returns the argv list(s) to remove the WG peer and mark the ephemeral identity revoked; idempotent.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_escalate.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "secubox-annuaire"))
import pytest
from assist import escalate as esc


def test_ephemeral_identity_flagged_and_unique():
    a = esc.mint_ephemeral_identity()
    b = esc.mint_ephemeral_identity()
    assert a["ephemeral"] is True
    assert a["did"].startswith("did:plc:") and len(a["did"]) == 40
    assert a["did"] != b["did"]
    assert len(bytes.fromhex(a["priv_hex"])) == 32


def test_peer_ip_must_be_in_ephemeral_range():
    argv = esc.add_ephemeral_peer("PUBKEY=", "1.2.3.4:51820", "10.11.0.7")
    assert isinstance(argv, list) and "10.11.0.7" in argv
    assert not any(";" in a for a in argv)  # never a shell string
    with pytest.raises(esc.EscalateError):
        esc.add_ephemeral_peer("PUBKEY=", "1.2.3.4:51820", "10.99.1.5")  # wrong range


def test_teardown_returns_argv_lists():
    cmds = esc.teardown("10.11.0.7", "did:plc:" + "a" * 32)
    assert cmds and all(isinstance(c, list) for c in cmds)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_escalate.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'assist.escalate'`.

- [ ] **Step 3: Implement `assist/escalate.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.escalate — multi-layer bootstrap for total-reach join.

Layer 1: an EPHEMERAL identity (throwaway Ed25519 key + DID), flagged
ephemeral, NEVER promoted to a persistent gondwana member. Layer 2: a
session-scoped WireGuard peer in EPHEMERAL_RANGE (10.11.0.0/24) on the
wg-ephemeral iface (established via secubox-p2p). teardown() removes both.
These builders return argv LISTS (shell=False); the privileged exec is done by
secubox-assistctl under a scoped sudoers entry — never in the web daemon.
"""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from typing import List

EPHEMERAL_RANGE = "10.11.0.0/24"
EPHEMERAL_IFACE = "wg-ephemeral"
_P2P = "/usr/sbin/secubox-p2pctl"  # secubox-p2p control CLI


class EscalateError(Exception):
    """Bad range, or a layer that cannot be established (fail-closed)."""


def mint_ephemeral_identity() -> dict:
    # Local, self-contained: annuaire.crypto is a runtime dep in prod.
    from annuaire.crypto import public_from_private, did_from_pubkey
    priv = os.urandom(32)
    did = did_from_pubkey(public_from_private(priv))
    return {"did": did, "priv_hex": priv.hex(), "ephemeral": True,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def _in_range(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(EPHEMERAL_RANGE)
    except ValueError:
        return False


def add_ephemeral_peer(pubkey: str, endpoint: str, ip: str) -> List[str]:
    if not _in_range(ip):
        raise EscalateError(f"ip {ip!r} outside ephemeral range {EPHEMERAL_RANGE}")
    return [_P2P, "peer-add", "--iface", EPHEMERAL_IFACE, "--ephemeral",
            "--pubkey", pubkey, "--endpoint", endpoint, "--allowed-ip", f"{ip}/32"]


def teardown(ip: str, did: str) -> List[List[str]]:
    return [
        [_P2P, "peer-del", "--iface", EPHEMERAL_IFACE, "--allowed-ip", f"{ip}/32"],
        [_P2P, "ephemeral-revoke", "--did", did],
    ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_escalate.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/assist/escalate.py packages/secubox-assist/tests/test_escalate.py
git commit -m "feat(assist): escalate.py — ephemeral identity + WG peer builders (mesh-range guarded) (ref assist-dual)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

**Note for reviewer/controller:** `secubox-p2pctl peer-add --ephemeral`/`ephemeral-revoke` subcommands are assumed on the `secubox-p2p` side. If they do not exist, Task 6 has a ⚠️ cross-package dependency: either add them to `secubox-p2p` (separate task) or adapt the argv to the existing p2p CLI. Confirm the real `secubox-p2p` CLI before wiring the exec in Task 8.

---

## Task 7: nft — open the assist WS port on wg-ephemeral too

**Files:**
- Modify: `packages/secubox-assist/nft/secubox-assist.nft`
- Test: `packages/secubox-assist/tests/test_packaging_dual.py` (nft assertion)

**Interfaces:** the shipped nft must accept the assist WS port on `iifname "wg-ephemeral"` in addition to `"wg-mesh"`, still `policy accept` (never a standalone drop — [[project_gk2_nginx_multimaster_blocker]] class), still no `0.0.0.0`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_packaging_dual.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_nft_covers_ephemeral_iface_mesh_only():
    nft = (ROOT / "nft" / "secubox-assist.nft").read_text()
    assert 'iifname "wg-mesh"' in nft
    assert 'iifname "wg-ephemeral"' in nft
    assert "0.0.0.0" not in nft
    assert "policy drop" not in nft  # never a standalone drop table
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_packaging_dual.py -q`
Expected: FAIL — `wg-ephemeral` not present.

- [ ] **Step 3: Implement** — add the ephemeral-iface accept line to `nft/secubox-assist.nft` (mirror the existing wg-mesh line):

```
        iifname "wg-ephemeral" tcp dport 8099 accept
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_packaging_dual.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/nft/secubox-assist.nft packages/secubox-assist/tests/test_packaging_dual.py
git commit -m "feat(assist): nft accepts assist WS on wg-ephemeral iface too (mesh-only, policy accept) (ref assist-dual)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 8: secubox-assistctl — offer/request/match/joinlink/join subcommands

**Files:**
- Modify: `packages/secubox-assist/sbin/secubox-assistctl`
- Test: `packages/secubox-assist/tests/test_assistctl_dual.py`

**Interfaces:**
- Consumes: `annuaire.verbs.assist_offer/offer_revoke/open_request/match_accept`, `annuaire.assist_match`, `assist.rendezvous`, `assist.joinlink`, `assist.escalate`, key at `ANNUAIRE_KEY_PATH`.
- Produces subcommands (JSON stdout; `{"error":...}` rc!=0 on rejection; `DRYRUN=1` writes nothing):
  - `offer --tags a,b --scope s --ttl 1800`, `offer-revoke <offer_id>`, `request-open --tags a --ttl 600 --reason x`, `match-accept <offer_id> <req_id> <offer|request>`, `matches` (list ready matches for self), `joinlink --for <ref> --ttl 900`, `join <token>` (redeem → escalate; execs the escalate argv under sudo).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_assistctl_dual.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, subprocess, sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-assistctl")
ANN = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
ASSIST = str(Path(__file__).resolve().parent.parent)


def _env(tmp_path):
    key = tmp_path / "node.key"; key.write_text("11" * 32)
    env = dict(os.environ)
    env.update(ANNUAIRE_KEY_PATH=str(key), ANNUAIRE_JOURNAL=str(tmp_path / "j.db"),
               ANNUAIRE_LIB=ANN, ASSIST_LIB=ASSIST,
               PYTHONPATH=os.pathsep.join([ANN, ASSIST, env.get("PYTHONPATH", "")]))
    return env


def test_offer_then_matches_lists(tmp_path):
    env = _env(tmp_path)
    r = subprocess.run([sys.executable, CTL, "offer", "--tags", "lora", "--ttl",
                        "3600"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout).get("offer_id")


def test_dryrun_writes_nothing(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    r = subprocess.run([sys.executable, CTL, "request-open", "--tags", "lora",
                        "--ttl", "600", "--reason", "x"], env=env,
                       capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_assistctl_dual.py -q`
Expected: FAIL (subcommands not present).

- [ ] **Step 3: Implement** — add the subcommands to `sbin/secubox-assistctl` following the existing pattern (`_key()`, `_journal()`, `_dry()`, `_die()`, argparse subparsers). Each mutating cmd: `if _dry(): print({"dryrun":True,...}); return` then `verbs.assist_*`. `offer`/`request-open` mint an `offer_id`/`req_id` = `"off-"+secrets.token_hex(8)` / `"orq-"+...`. `matches` prints `rendezvous.ready_matches(list(journal.iter_entries()), self_did, now)`. `joinlink` calls `joinlink.mint_join`, journals only the hash (a small `ASSIST`-adjacent note is out of scope — print the url+token_hash). `join <token>` redeems: validate not-expired + hash match, then build `escalate.mint_ephemeral_identity()` + `escalate.add_ephemeral_peer(...)` and exec the argv (real p2p wiring per Task 6 note). Wrap every verb call in `try/except ValueError as exc: _die(str(exc))` (the socle's error-contract lesson).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_assistctl_dual.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-assist/sbin/secubox-assistctl packages/secubox-assist/tests/test_assistctl_dual.py
git commit -m "feat(assist): assistctl offer/request-open/match-accept/joinlink/join (ref assist-dual)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 9: API — marketplace endpoints (reads in-process, writes via ctl)

**Files:**
- Modify: `packages/secubox-assist/api/main.py`
- Test: `packages/secubox-assist/tests/test_api_dual.py`

**Interfaces:** JWT-gated except `/status`+`/health`. New: `GET /offers`, `POST /offer`, `POST /offer/revoke`, `GET /requests/open`, `POST /request/open`, `GET /matches`, `POST /match/accept`, `POST /joinlink`. Reads call `annuaire.assist_match`/`rendezvous` in-process; writes shell to `secubox-assistctl` (list argv, rc!=0 → `HTTPException(400)`).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-assist/tests/test_api_dual.py — abbreviated
import os, sys
from pathlib import Path
ANN = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
sys.path.insert(0, ANN); sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/assist-dual-test.db")
from fastapi.testclient import TestClient
from api.main import app
client = TestClient(app)


def test_offers_public_read_or_gated():
    r = client.get("/matches")
    assert r.status_code in (200, 401, 403)  # /matches is JWT-gated


def test_offer_requires_jwt():
    r = client.post("/offer", json={"tags": ["lora"], "ttl_s": 600})
    assert r.status_code in (401, 403)
```

- [ ] **Step 2-4:** implement the endpoints mirroring the socle's `_ctl()` + in-process read pattern; run `cd packages/secubox-assist && ../../.venv/bin/pytest tests/test_api_dual.py -q` red→green.

- [ ] **Step 5: Commit** `feat(assist): /offers /requests/open /matches /match/accept /joinlink API (ref assist-dual)` + Co-Authored-By trailer.

---

## Task 10: /assist panel tabs (Disponibilité/Demander/Matches/Inviter/Rejoindre)

**Files:**
- Modify: `packages/secubox-assist/www/assist/index.html`
- Test: `packages/secubox-assist/tests/test_menu.py` (extend — assert new tab hooks, still no inline `onclick`, still `sbx_token`).

- [ ] **Steps:** add the five tabs, event-delegated (no inline handlers), all dynamic values via `textContent` (XSS guard), reading `/api/v1/assist/{offers,requests/open,matches}` and POSTing offer/request/match-accept/joinlink; "Rejoindre" pastes a link and shows escalation status. Red→green on the extended menu test. Commit with trailer.

---

## Task 11: packaging — deps, changelog, p2p ephemeral range, install

**Files:**
- Modify: `packages/secubox-assist/debian/{changelog,control,rules,secubox-assist.install}`, add p2p ephemeral-range provisioning (postinst or a p2p drop-in for `wg-ephemeral` `10.11.0.0/24`).
- Test: `packages/secubox-assist/tests/test_packaging_dual.py` (extend — install ships `rendezvous.py`, `joinlink.py`, `escalate.py`; sudoers still scoped; postinst no shared-parent chown).

- [ ] **Steps:** bump `secubox-assist` changelog to `0.2.0-1~bookworm1`; ensure the new modules ship (glob covers `assist/*.py`); add `secubox-p2p` to `Depends` (ephemeral WG); provision the `wg-ephemeral` iface/range via a p2p drop-in (idempotent, postinst, never chown shared parents). Bump `secubox-annuaire` changelog (ships `assist_match.py`). Build both `.deb`. Red→green + `dpkg-buildpackage -us -uc -b` for both. Commit with trailer.

---

## Self-Review

**1. Spec coverage:** OFFER/REQUEST/MATCH_ACCEPT ops+models → T1. Decentralized matcher (tags∩, scope, expiry, match_id, match_ready) → T2. Signed verbs → T3. Mutual double-accept → requester SESSION_OPEN (sovereign) → T4. Join-link single-use hash-only → T5. Multi-layer escalate (ephemeral identity + WG peer 10.11.0.0/24 + teardown) → T6. nft wg-ephemeral mesh-only → T7. ctl → T8. API → T9. Panel tabs → T10. Packaging (+secubox-p2p, ephemeral range) → T11. ✅
**2. Placeholder scan:** T9/T10/T11 use compressed step bodies (mirror-the-socle) rather than full code — acceptable because they replicate the already-shipped socle API/panel/packaging patterns verbatim; the novel logic (T1-T8) carries complete code. Flag to implementer: follow the socle files as the template.
**3. Type consistency:** `match_id(offer_id, req_id)` identical across T2/T3/T4. `matches()->[(offer,request,mid)]` consumed unchanged in T4. `mint_join()->dict` keys used in T8. `add_ephemeral_peer(pubkey,endpoint,ip)` / `teardown(ip,did)` consistent T6↔T8. `_by` reused from socle `assist.py`. ✅

**Cross-task ⚠️ for the controller:** Task 6/8 assume `secubox-p2pctl peer-add --ephemeral`/`ephemeral-revoke`. Confirm the real `secubox-p2p` CLI before Task 8 wires the exec; if absent, insert a `secubox-p2p` task (ephemeral peer support) before Task 8. This is the one genuine cross-package dependency in the plan.
