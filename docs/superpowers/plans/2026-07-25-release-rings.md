<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Progressive Release Rings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver SecuBox artifacts (deb/image/www) through center-driven promotion rings `draft → internal → published` on `apt.secubox.in`, where a center holding a `capability="release"` grant promotes evolutions and assigns per-box rings — honored sovereignly (only granted centers), 4R-fail-safe on the box, GPG-signed end-to-end.

**Architecture:** Pure control-plane on the `secubox-annuaire` journal (`RELEASE_*` ops + a pure resolver `releases.py` + grant-gated signed verbs), plus two actuators: a repo actuator (`secubox-release-repo`, `reprepro copy` between ring distributions, op-gated) and a box actuator (`secubox-releasectl apply`, a 4R sources drop-in swap + targeted `apt`). Reuses the Centres & Grants grant machinery and the `apt.secubox.in` reprepro repo verbatim.

**Tech Stack:** Python 3.11, Ed25519 (`annuaire.crypto`), reprepro, apt, FastAPI/uvicorn (API on a unix socket), pytest.

## Global Constraints

- **SPDX header** (verbatim) on every new Python/Bash file:
  ```
  # SPDX-License-Identifier: LicenseRef-CMSD-1.0
  # Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  # Source-Disclosed License — All rights reserved except as expressly granted.
  # See LICENCE-CMSD-1.0.md for terms.
  ```
- **`RINGS = ["draft", "internal", "published"]`** — fixed order; `PROMOTE` advances exactly ONE step, `DEMOTE` retreats one; NEVER skip a ring.
- **Grant-gated + sovereign:** `release_promote`/`ring_assign` require an active `active_grants(entries, self_did)` grant with `capability == "release"` for the emitting center, else reject. The box honors a ring op ONLY from a center it granted (`issued_by == self_did` on the grant — sovereignty). Default box ring = `published`.
- **apt GPG end-to-end:** `reprepro copy` re-signs the target distribution; the box verifies GPG at `apt update`. Promotion NEVER bypasses signing. NEVER publish an evolution lacking an `arm64` artifact (would brick arm64 boards).
- **4R fail-safe on the box:** the ring switch writes a SHADOW drop-in → `apt update` validates → atomic swap → rollback-on-failure. NEVER touch the main `/etc/apt/sources.list`; only `/etc/apt/sources.list.d/secubox-ring.list`. A failed apt must restore the previous ring, never brick the box.
- **No privileged action in-process:** the API delegates every mutation to `secubox-releasectl`; the ctl runs `reprepro`/`apt` under a scoped sudoers. NEVER chown the shared parents `/run/secubox`, `/etc/secubox`, `/var/log/secubox`, `/var/lib/secubox`, `/data/apt` (chmod only if needed).
- **Audit append-only** `/var/log/secubox/audit.log`: publish/promote/demote/assign + box apply/rollback.
- **DID pattern** `^did:plc:[0-9a-f]{32}$`. Versioning `X.Y.Z-1~bookworm1`; `#DEBHELPER#` alone on its line. Commit messages end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO AI/Claude references.
- Tests: repo `.venv`, per-directory (`cd packages/<pkg> && ../../.venv/bin/pytest tests/…`).

## Substrate reference (reuse, do not reinvent)

- `annuaire/model.py`: `class Op(str, Enum)` (add members after the assist block), `now_rfc3339()`, `Grant` (has `capability` default `"config"`), DID pattern.
- `annuaire/grants.py`: `active_grants(entries, self_did) -> {(scope, layer): grant_payload}` (sovereignty: keeps only `issued_by == self_did` when self_did given), `_op(entry)`/`_payload(entry)` (dict/LogEntry tolerant), `validate_issue`.
- `annuaire/verbs.py`: signing idiom — build `payload` dict (incl `"created_at": now_rfc3339()`), `sig = sign(priv, canonical_bytes(payload))`, `journal.append(op=…, payload_type="…", payload=payload, author=did, author_pubkey_hex=pub_hex, sig=sig)`. `did_from_pubkey(public_from_private(priv))`. See `grant_issue`.
- `apt.secubox.in`: reprepro base `/data/apt` on gk2, `conf/distributions` currently has `stable`(bookworm)/`testing`(bookworm-testing), Architectures `arm64 amd64 source`, Components `main contrib`. GPG-signed (key 219BA). This plan ADDS ring distributions `draft`/`internal`/`published`.
- 4R pattern: `profilectl apply/rollback` (shadow → validate → atomic `os.replace` → rollback) — template for the box actuator.

## File Structure

**Control-plane — `packages/secubox-annuaire/`:**
- `annuaire/model.py` — +4 `Op` members, +3 models (`Evolution`, `RingState`, `RingAssign`), `RINGS`.
- `annuaire/releases.py` (new) — pure resolver.
- `annuaire/verbs.py` — +4 verbs (grant-gated).
- `tests/test_release_model.py`, `tests/test_releases.py`, `tests/test_release_verbs.py`.

**New package — `packages/secubox-release/`:**
- `release/repo.py` (new) — reprepro-copy actuator logic (op-gated argv builders + apply).
- `release/boxapply.py` (new) — 4R sources drop-in builder + ring resolution (pure) + apt wrapper.
- `sbin/secubox-releasectl` (new) — CLI (publish/promote/demote/assign/sync-repo/apply).
- `sbin/secubox-release-repo` (new) — repo-host actuator entrypoint.
- `api/main.py` (new) — FastAPI `/releases/*` (reads in-process, writes → ctl).
- `www/releases/index.html`, `menu.d/590-releases.json`, `nginx/releases.conf`.
- `systemd/secubox-release-api.service`, `debian/*`, `sudoers/secubox-release`.
- `tests/test_repo.py`, `tests/test_boxapply.py`, `tests/test_releasectl.py`, `tests/test_api.py`, `tests/test_packaging.py`, `conftest.py`, `pytest.ini`.

---

## Task 1: annuaire model — release ops + Evolution/RingState/RingAssign

**Files:**
- Modify: `packages/secubox-annuaire/annuaire/model.py`
- Test: `packages/secubox-annuaire/tests/test_release_model.py`

**Interfaces — Produces:**
- `Op.RELEASE_PUBLISH="release_publish"`, `Op.RELEASE_PROMOTE="release_promote"`, `Op.RELEASE_DEMOTE="release_demote"`, `Op.RING_ASSIGN="ring_assign"`.
- `RINGS = ["draft", "internal", "published"]`.
- `Artifact(kind:str["deb"|"image"|"www"], name:str, version:str, hash:str, arch:Optional[str])`.
- `Evolution(evo_id:str, artifacts:list[Artifact][min 1], notes:str, issued_by:str[DID], created_at, sig, signer_did)`.
- `RingState(evo_id:str, ring:str[in RINGS], issued_by:str[DID], created_at, sig, signer_did)`.
- `RingAssign(box_did:str[DID], ring:str[in RINGS], issued_by:str[DID], created_at, sig, signer_did)`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_release_model.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from pydantic import ValidationError
from annuaire.model import (Op, RINGS, Artifact, Evolution, RingState, RingAssign)

DID = "did:plc:" + "a" * 32


def test_ops_and_rings():
    assert Op.RELEASE_PROMOTE == "release_promote"
    assert Op.RING_ASSIGN == "ring_assign"
    assert RINGS == ["draft", "internal", "published"]


def test_evolution_needs_artifact_and_forbids_extra():
    e = Evolution(evo_id="e1", artifacts=[Artifact(kind="deb", name="secubox-dpi",
                  version="1.2.3", hash="ab", arch="arm64")], notes="x", issued_by=DID)
    assert e.artifacts[0].name == "secubox-dpi"
    with pytest.raises(ValidationError):
        Evolution(evo_id="e1", artifacts=[], notes="x", issued_by=DID)
    with pytest.raises(ValidationError):
        Evolution(evo_id="e1", artifacts=[Artifact(kind="deb", name="x", version="1",
                  hash="ab")], notes="x", issued_by=DID, sneaky=True)


def test_ringstate_and_assign_reject_bad_ring():
    RingState(evo_id="e1", ring="internal", issued_by=DID)
    RingAssign(box_did=DID, ring="published", issued_by=DID)
    with pytest.raises(ValidationError):
        RingState(evo_id="e1", ring="prod", issued_by=DID)
    with pytest.raises(ValidationError):
        RingAssign(box_did=DID, ring="prod", issued_by=DID)


def test_artifact_kind_validated():
    with pytest.raises(ValidationError):
        Artifact(kind="rpm", name="x", version="1", hash="ab")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_release_model.py -q`
Expected: FAIL — `ImportError: cannot import name 'RINGS'`.

- [ ] **Step 3: Implement**

In `annuaire/model.py`, add to `class Op` after the assist marketplace members:

```python
    # Progressive release rings (center-driven artifact delivery)
    RELEASE_PUBLISH = "release_publish"   # register an evolution (born in draft)
    RELEASE_PROMOTE = "release_promote"   # advance an evolution one ring
    RELEASE_DEMOTE  = "release_demote"    # retreat an evolution one ring
    RING_ASSIGN     = "ring_assign"       # a center assigns a box's ring
```

After the assist models, add:

```python
RINGS = ["draft", "internal", "published"]
_ARTIFACT_KINDS = {"deb", "image", "www"}


class Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind:    str = Field(..., description="'deb' | 'image' | 'www'")
    name:    str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    hash:    str = Field(..., min_length=1, description="content hash")
    arch:    Optional[str] = Field(default=None, description="e.g. 'arm64'; None for www")

    @field_validator("kind")
    @classmethod
    def _kind_known(cls, v: str) -> str:
        if v not in _ARTIFACT_KINDS:
            raise ValueError(f"kind must be one of {sorted(_ARTIFACT_KINDS)}")
        return v


def _ring_validator(v: str) -> str:
    if v not in RINGS:
        raise ValueError(f"ring must be one of {RINGS}")
    return v


class Evolution(BaseModel):
    """A signed, versioned artifact set promoted through rings (born in draft)."""
    model_config = ConfigDict(extra="forbid")
    evo_id:     str = Field(..., description="stable id for this evolution")
    artifacts:  list[Artifact] = Field(..., min_length=1)
    notes:      str = Field(default="", max_length=1024)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None


class RingState(BaseModel):
    """A signed ring transition for an evolution (promote/demote target)."""
    model_config = ConfigDict(extra="forbid")
    evo_id:     str = Field(...)
    ring:       str = Field(...)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None

    @field_validator("ring")
    @classmethod
    def _ring(cls, v: str) -> str:
        return _ring_validator(v)


class RingAssign(BaseModel):
    """A signed per-box ring assignment issued by a center."""
    model_config = ConfigDict(extra="forbid")
    box_did:    str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    ring:       str = Field(...)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None

    @field_validator("ring")
    @classmethod
    def _ring(cls, v: str) -> str:
        return _ring_validator(v)
```

Ensure `field_validator`, `Optional`, `ConfigDict`, `Field`, `now_rfc3339` are imported (they are).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_release_model.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/model.py packages/secubox-annuaire/tests/test_release_model.py
git commit -m "feat(annuaire): release ops + Evolution/RingState/RingAssign models (ref release-rings)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 2: annuaire releases.py — pure resolver (current ring, box ring, sovereignty)

**Files:**
- Create: `packages/secubox-annuaire/annuaire/releases.py`
- Test: `packages/secubox-annuaire/tests/test_releases.py`

**Interfaces:**
- Consumes: `annuaire.grants._op`/`_payload`/`active_grants`, `annuaire.model.Op`/`RINGS`.
- Produces:
  - `current_ring(entries, evo_id) -> str` — the ring of `evo_id` = the last `RELEASE_PROMOTE`/`RELEASE_DEMOTE` for it, else `"draft"` if a `RELEASE_PUBLISH` exists, else `None`.
  - `next_ring(ring) -> Optional[str]` / `prev_ring(ring) -> Optional[str]` — one step along `RINGS`, or None at the ends.
  - `box_ring(entries, box_did, self_did) -> str` — the last `RING_ASSIGN{box_did}` whose author holds an active `capability="release"` grant issued by `self_did`; default `"published"`.
  - `evolutions_in_ring(entries, ring) -> list[str]` — evo_ids currently in `ring`.
  - `has_release_grant(entries, center_did, self_did) -> bool` — an active grant with `capability=="release"` and `center_did` matches, issued by self_did.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_releases.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from annuaire.model import Op
from annuaire import releases as rl

BOX = "did:plc:" + "1" * 32
CENTER = "did:plc:" + "2" * 32
OTHER = "did:plc:" + "3" * 32


def e(op, **p):
    return {"op": op.value, "payload": p, "author": p.get("issued_by")}


def _grant(center, by=BOX, gid="g1"):
    return e(Op.GRANT_ISSUE, grant_id=gid, center_did=center, capability="release",
             scope="release", layer="baseline", issued_by=by)


def test_current_ring_defaults_and_transitions():
    entries = [e(Op.RELEASE_PUBLISH, evo_id="e1", issued_by=CENTER)]
    assert rl.current_ring(entries, "e1") == "draft"
    entries.append(e(Op.RELEASE_PROMOTE, evo_id="e1", ring="internal", issued_by=CENTER))
    assert rl.current_ring(entries, "e1") == "internal"
    entries.append(e(Op.RELEASE_DEMOTE, evo_id="e1", ring="draft", issued_by=CENTER))
    assert rl.current_ring(entries, "e1") == "draft"
    assert rl.current_ring(entries, "nope") is None


def test_next_prev_ring():
    assert rl.next_ring("draft") == "internal"
    assert rl.next_ring("published") is None
    assert rl.prev_ring("internal") == "draft"
    assert rl.prev_ring("draft") is None


def test_box_ring_default_published_and_granted():
    # no assignment -> published
    assert rl.box_ring([], BOX, self_did=BOX) == "published"
    entries = [_grant(CENTER), e(Op.RING_ASSIGN, box_did=BOX, ring="internal", issued_by=CENTER)]
    assert rl.box_ring(entries, BOX, self_did=BOX) == "internal"


def test_box_ring_sovereignty_ignores_ungranted_center():
    # OTHER assigns but has no release grant from BOX -> ignored, default published
    entries = [e(Op.RING_ASSIGN, box_did=BOX, ring="internal", issued_by=OTHER)]
    assert rl.box_ring(entries, BOX, self_did=BOX) == "published"


def test_evolutions_in_ring():
    entries = [e(Op.RELEASE_PUBLISH, evo_id="e1", issued_by=CENTER),
               e(Op.RELEASE_PUBLISH, evo_id="e2", issued_by=CENTER),
               e(Op.RELEASE_PROMOTE, evo_id="e1", ring="internal", issued_by=CENTER)]
    assert rl.evolutions_in_ring(entries, "internal") == ["e1"]
    assert rl.evolutions_in_ring(entries, "draft") == ["e2"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_releases.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'annuaire.releases'`.

- [ ] **Step 3: Implement `annuaire/releases.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire.releases — pure resolver for center-driven release rings.

Every node computes the current ring of each evolution and its own assigned ring
from its journal copy. SOVEREIGNTY: a RING_ASSIGN counts only when its author
holds an active capability="release" grant issued BY THIS BOX (self_did) — a
peer's assignment is ignored. Default ring is "published".
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional

from .grants import _op, _payload, active_grants
from .model import Op, RINGS


def _by(entries, op: Op):
    for entry in entries:
        if _op(entry) == op.value:
            yield _payload(entry)


def _author(entry) -> Optional[str]:
    if isinstance(entry, dict):
        return entry.get("author")
    return getattr(entry, "author", None)


def next_ring(ring: str) -> Optional[str]:
    i = RINGS.index(ring)
    return RINGS[i + 1] if i + 1 < len(RINGS) else None


def prev_ring(ring: str) -> Optional[str]:
    i = RINGS.index(ring)
    return RINGS[i - 1] if i > 0 else None


def current_ring(entries: List[Mapping[str, Any]], evo_id: str) -> Optional[str]:
    published = {p.get("evo_id") for p in _by(entries, Op.RELEASE_PUBLISH)}
    if evo_id not in published:
        return None
    ring = "draft"
    for op in (Op.RELEASE_PROMOTE, Op.RELEASE_DEMOTE):
        pass  # handled below in order
    for entry in entries:
        o = _op(entry)
        if o in (Op.RELEASE_PROMOTE.value, Op.RELEASE_DEMOTE.value):
            p = _payload(entry)
            if p.get("evo_id") == evo_id and p.get("ring") in RINGS:
                ring = p["ring"]
    return ring


def evolutions_in_ring(entries: List[Mapping[str, Any]], ring: str) -> List[str]:
    ids = [p.get("evo_id") for p in _by(entries, Op.RELEASE_PUBLISH)]
    return [i for i in ids if current_ring(entries, i) == ring]


def has_release_grant(entries: List[Mapping[str, Any]], center_did: str,
                      self_did: str) -> bool:
    for g in active_grants(entries, self_did).values():
        if g.get("capability") == "release" and g.get("center_did") == center_did:
            return True
    return False


def box_ring(entries: List[Mapping[str, Any]], box_did: str, self_did: str) -> str:
    ring = "published"
    for entry in entries:
        if _op(entry) != Op.RING_ASSIGN.value:
            continue
        p = _payload(entry)
        if p.get("box_did") != box_did or p.get("ring") not in RINGS:
            continue
        author = _author(entry) or p.get("issued_by")
        if has_release_grant(entries, author, self_did):
            ring = p["ring"]
    return ring
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_releases.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/releases.py packages/secubox-annuaire/tests/test_releases.py
git commit -m "feat(annuaire): releases.py — pure resolver (ring state, box ring, sovereignty) (ref release-rings)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 3: annuaire verbs — grant-gated signed release ops

**Files:**
- Modify: `packages/secubox-annuaire/annuaire/verbs.py`
- Test: `packages/secubox-annuaire/tests/test_release_verbs.py`

**Interfaces:**
- Consumes: `sign`, `canonical_bytes`, `public_from_private`, `did_from_pubkey`, `Op`, `now_rfc3339`, `Evolution/RingState/RingAssign`, `releases.current_ring/next_ring/prev_ring/has_release_grant`.
- Produces (each returns the appended `LogEntry`):
  - `release_publish(journal, priv, artifacts, notes, evo_id) -> LogEntry` — signs an `Evolution` (born draft; no grant needed to publish your own evolution).
  - `release_promote(journal, priv, self_did, evo_id) -> LogEntry` — advances ONE ring; raises `ValueError` if the emitter lacks a `capability="release"` grant from `self_did`, or the evolution is already `published`, or absent.
  - `release_demote(journal, priv, self_did, evo_id) -> LogEntry` — retreats one; same grant gate; raises at `draft`.
  - `ring_assign(journal, priv, self_did, box_did, ring) -> LogEntry` — same grant gate; raises if `ring not in RINGS`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_release_verbs.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
import pytest
from annuaire.log import Journal
from annuaire.crypto import public_from_private, did_from_pubkey
from annuaire import verbs, releases as rl
from annuaire.model import Op


def _key():
    p = os.urandom(32)
    return p, did_from_pubkey(public_from_private(p))


def test_publish_born_draft(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    cpriv, cdid = _key()
    verbs.release_publish(j, cpriv, [{"kind": "deb", "name": "secubox-dpi",
        "version": "1.2.3", "hash": "ab", "arch": "arm64"}], "note", evo_id="e1")
    assert rl.current_ring(list(j.iter_entries()), "e1") == "draft"


def test_promote_requires_release_grant(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    bpriv, bdid = _key()      # the box
    cpriv, cdid = _key()      # the center
    verbs.release_publish(j, cpriv, [{"kind": "deb", "name": "x", "version": "1",
        "hash": "ab", "arch": "arm64"}], "n", evo_id="e1")
    # no grant yet -> promote by center rejected on the box's view
    with pytest.raises(ValueError):
        verbs.release_promote(j, cpriv, bdid, "e1")
    # box grants release to center
    verbs.grant_issue(j, bpriv, bdid, cdid, scope="release", layer="baseline",
                      capability="release")
    verbs.release_promote(j, cpriv, bdid, "e1")
    assert rl.current_ring(list(j.iter_entries()), "e1") == "internal"


def test_ring_assign_requires_grant(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    bpriv, bdid = _key(); cpriv, cdid = _key()
    with pytest.raises(ValueError):
        verbs.ring_assign(j, cpriv, bdid, bdid, "internal")
    verbs.grant_issue(j, bpriv, bdid, cdid, scope="release", layer="baseline",
                      capability="release")
    verbs.ring_assign(j, cpriv, bdid, bdid, "internal")
    assert rl.box_ring(list(j.iter_entries()), bdid, self_did=bdid) == "internal"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_release_verbs.py -q`
Expected: FAIL — `AttributeError: module 'annuaire.verbs' has no attribute 'release_publish'`.

- [ ] **Step 3: Implement** (append to `annuaire/verbs.py`; add `from .model import Evolution, RingState, RingAssign` and `from . import releases`)

```python
# --- Progressive release rings -------------------------------------------

def _release_append(journal, priv, op, model_obj, payload_type):
    payload = model_obj.model_dump(exclude={"sig", "signer_did"})
    pub_hex = public_from_private(priv).hex()
    author = did_from_pubkey(public_from_private(priv))
    sig = sign(priv, canonical_bytes(payload))
    return journal.append(op=op, payload=payload, payload_type=payload_type,
                          author=author, author_pubkey_hex=pub_hex, sig=sig)


def release_publish(journal, priv, artifacts, notes, evo_id):
    did = did_from_pubkey(public_from_private(priv))
    m = Evolution(evo_id=evo_id, artifacts=list(artifacts), notes=notes, issued_by=did)
    return _release_append(journal, priv, Op.RELEASE_PUBLISH, m, "Evolution")


def _require_release_grant(journal, priv, self_did):
    center = did_from_pubkey(public_from_private(priv))
    entries = list(journal.iter_entries())
    if not releases.has_release_grant(entries, center, self_did):
        raise ValueError("no-release-grant")
    return entries


def release_promote(journal, priv, self_did, evo_id):
    entries = _require_release_grant(journal, priv, self_did)
    cur = releases.current_ring(entries, evo_id)
    if cur is None:
        raise ValueError("no-such-evolution")
    nxt = releases.next_ring(cur)
    if nxt is None:
        raise ValueError("already-published")
    m = RingState(evo_id=evo_id, ring=nxt, issued_by=did_from_pubkey(public_from_private(priv)))
    return _release_append(journal, priv, Op.RELEASE_PROMOTE, m, "RingState")


def release_demote(journal, priv, self_did, evo_id):
    entries = _require_release_grant(journal, priv, self_did)
    cur = releases.current_ring(entries, evo_id)
    if cur is None:
        raise ValueError("no-such-evolution")
    prv = releases.prev_ring(cur)
    if prv is None:
        raise ValueError("already-draft")
    m = RingState(evo_id=evo_id, ring=prv, issued_by=did_from_pubkey(public_from_private(priv)))
    return _release_append(journal, priv, Op.RELEASE_DEMOTE, m, "RingState")


def ring_assign(journal, priv, self_did, box_did, ring):
    _require_release_grant(journal, priv, self_did)
    m = RingAssign(box_did=box_did, ring=ring,
                   issued_by=did_from_pubkey(public_from_private(priv)))
    return _release_append(journal, priv, Op.RING_ASSIGN, m, "RingAssign")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_release_verbs.py tests/test_releases.py tests/test_release_model.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/verbs.py packages/secubox-annuaire/tests/test_release_verbs.py
git commit -m "feat(annuaire): release_publish/promote/demote/ring_assign grant-gated verbs (ref release-rings)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 4: secubox-release package scaffold + repo actuator logic

**Files:**
- Create: `packages/secubox-release/release/__init__.py` (empty), `release/repo.py`, `conftest.py`, `pytest.ini`, minimal `debian/{control,compat,changelog,rules}`.
- Test: `packages/secubox-release/tests/test_repo.py`

**Interfaces — Produces (`release/repo.py`):**
- `REPREPRO_BASE = os.environ.get("SECUBOX_APT_BASE", "/data/apt")`.
- `RING_DISTS = {"draft": "draft", "internal": "internal", "published": "published"}` (ring → reprepro distribution codename).
- `class RepoError(Exception)`.
- `has_arch(artifacts, arch="arm64") -> bool` — True iff some `deb` artifact has `arch=="arm64"`.
- `copy_argv(from_ring, to_ring, pkg_names) -> list[str]` — `["reprepro", "-b", REPREPRO_BASE, "copy", RING_DISTS[to_ring], RING_DISTS[from_ring], *pkg_names]`; raises `RepoError` if either ring unknown or `pkg_names` empty.
- `plan_promote(evolution, from_ring, to_ring) -> list[list[str]]` — refuses (`RepoError`) if `not has_arch(evolution["artifacts"])` (never publish amd64-only); returns the argv list(s) to run.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-release/tests/test_repo.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from release import repo


def test_copy_argv_is_list_no_shell():
    argv = repo.copy_argv("draft", "internal", ["secubox-dpi"])
    assert argv[0] == "reprepro" and "copy" in argv and "secubox-dpi" in argv
    assert not any(";" in a for a in argv)
    with pytest.raises(repo.RepoError):
        repo.copy_argv("draft", "internal", [])
    with pytest.raises(repo.RepoError):
        repo.copy_argv("draft", "prod", ["x"])


def test_plan_promote_refuses_amd64_only():
    evo_ok = {"artifacts": [{"kind": "deb", "name": "secubox-dpi", "arch": "arm64"}]}
    evo_bad = {"artifacts": [{"kind": "deb", "name": "secubox-dpi", "arch": "amd64"}]}
    assert repo.plan_promote(evo_ok, "draft", "internal")
    with pytest.raises(repo.RepoError):
        repo.plan_promote(evo_bad, "draft", "internal")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-release && ../../.venv/bin/pytest tests/test_repo.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'release'`.

- [ ] **Step 3: Implement scaffold + `release/repo.py`**

`release/__init__.py`: empty. `conftest.py`: `import sys, os; sys.path.insert(0, os.path.dirname(__file__))`. `pytest.ini`: `[pytest]` (no special config yet).

`release/repo.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: release.repo — reprepro-copy actuator (op-gated argv builders)."""
from __future__ import annotations

import os
from typing import List

REPREPRO_BASE = os.environ.get("SECUBOX_APT_BASE", "/data/apt")
RING_DISTS = {"draft": "draft", "internal": "internal", "published": "published"}


class RepoError(Exception):
    """Unknown ring, empty package set, or a promotion that would brick arm64."""


def has_arch(artifacts, arch: str = "arm64") -> bool:
    return any(a.get("kind") == "deb" and a.get("arch") == arch for a in artifacts)


def copy_argv(from_ring: str, to_ring: str, pkg_names: List[str]) -> List[str]:
    if from_ring not in RING_DISTS or to_ring not in RING_DISTS:
        raise RepoError(f"unknown ring {from_ring!r}/{to_ring!r}")
    if not pkg_names:
        raise RepoError("no packages to copy")
    return ["reprepro", "-b", REPREPRO_BASE, "copy", RING_DISTS[to_ring],
            RING_DISTS[from_ring], *pkg_names]


def plan_promote(evolution: dict, from_ring: str, to_ring: str) -> List[List[str]]:
    artifacts = evolution.get("artifacts", [])
    debs = [a["name"] for a in artifacts if a.get("kind") == "deb"]
    if debs and not has_arch(artifacts, "arm64"):
        raise RepoError("evolution has no arm64 deb — refusing to publish (would brick arm64)")
    return [copy_argv(from_ring, to_ring, debs)] if debs else []
```

Minimal `debian/control` (`Source: secubox-release`, `Package: secubox-release`, `Architecture: all`, `Depends: ${python3:Depends}, ${misc:Depends}, python3-fastapi, python3-uvicorn, secubox-core, secubox-annuaire, reprepro`), `debian/compat`=13, `debian/changelog` (`0.1.0-1~bookworm1`), `debian/rules` (`#!/usr/bin/make -f` / `%:` / `\tdh $@ --with python3`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-release && ../../.venv/bin/pytest tests/test_repo.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-release/release packages/secubox-release/tests/test_repo.py packages/secubox-release/conftest.py packages/secubox-release/pytest.ini packages/secubox-release/debian
git commit -m "feat(release): package scaffold + reprepro-copy actuator (arm64-guard, op-gated argv) (ref release-rings)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 5: box actuator — 4R sources drop-in + ring resolution (pure)

**Files:**
- Create: `packages/secubox-release/release/boxapply.py`
- Test: `packages/secubox-release/tests/test_boxapply.py`

**Interfaces:**
- Produces:
  - `RING_LIST_PATH = "/etc/apt/sources.list.d/secubox-ring.list"`, `APT_BASE_URL = "https://apt.secubox.in"`.
  - `sources_line(ring) -> str` — `f"deb {APT_BASE_URL} {ring} main contrib"` (ring in RINGS else `ValueError`).
  - `class ApplyError(Exception)`.
  - `apply_4r(ring, target_path, apt_update_fn) -> dict` — writes a SHADOW file (`target_path + ".shadow"`), calls `apt_update_fn(shadow_path)` (injected; returns True on success), on success atomically `os.replace(shadow, target_path)` keeping a `.rollback` copy of the prior; on failure restores the prior and raises `ApplyError`. Returns `{"ring", "applied": bool}`. NEVER writes the main sources.list. Pure enough to unit-test with a fake `apt_update_fn` and a tmp `target_path`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-release/tests/test_boxapply.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from release import boxapply as bx


def test_sources_line():
    assert bx.sources_line("internal") == "deb https://apt.secubox.in internal main contrib"
    with pytest.raises(ValueError):
        bx.sources_line("prod")


def test_apply_4r_swaps_on_success(tmp_path):
    target = tmp_path / "secubox-ring.list"
    target.write_text("deb https://apt.secubox.in published main contrib\n")
    r = bx.apply_4r("internal", str(target), apt_update_fn=lambda p: True)
    assert r["applied"] is True
    assert "internal" in target.read_text()


def test_apply_4r_rolls_back_on_apt_failure(tmp_path):
    target = tmp_path / "secubox-ring.list"
    target.write_text("deb https://apt.secubox.in published main contrib\n")
    with pytest.raises(bx.ApplyError):
        bx.apply_4r("internal", str(target), apt_update_fn=lambda p: False)
    # prior 'published' ring preserved — box not bricked
    assert "published" in target.read_text()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-release && ../../.venv/bin/pytest tests/test_boxapply.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'release.boxapply'`.

- [ ] **Step 3: Implement `release/boxapply.py`**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: release.boxapply — 4R ring switch for the box's apt sources.

Writes ONLY the ring drop-in (/etc/apt/sources.list.d/secubox-ring.list), never
the main sources.list. Shadow → validate (apt update) → atomic swap → rollback
on failure, so a bad ring never bricks the box.
"""
from __future__ import annotations

import os
import shutil

from annuaire.model import RINGS  # ring names

RING_LIST_PATH = "/etc/apt/sources.list.d/secubox-ring.list"
APT_BASE_URL = "https://apt.secubox.in"


class ApplyError(Exception):
    """apt validation failed; the prior ring was restored."""


def sources_line(ring: str) -> str:
    if ring not in RINGS:
        raise ValueError(f"ring must be one of {RINGS}")
    return f"deb {APT_BASE_URL} {ring} main contrib"


def apply_4r(ring, target_path, apt_update_fn) -> dict:
    shadow = target_path + ".shadow"
    rollback = target_path + ".rollback"
    prior = None
    if os.path.exists(target_path):
        prior = open(target_path).read()
        shutil.copy(target_path, rollback)
    with open(shadow, "w") as fh:
        fh.write(sources_line(ring) + "\n")
    ok = False
    try:
        ok = bool(apt_update_fn(shadow))
    except Exception:
        ok = False
    if not ok:
        # restore prior ring; drop the shadow
        if prior is not None:
            with open(target_path, "w") as fh:
                fh.write(prior)
        try:
            os.remove(shadow)
        except OSError:
            pass
        raise ApplyError(f"apt validation failed for ring {ring!r}; restored prior")
    os.replace(shadow, target_path)  # atomic
    return {"ring": ring, "applied": True}
```

Note: `annuaire.model` is on `sys.path` in prod (`/usr/lib/secubox/annuaire`) and in tests via the package `pytest.ini` — Task 9 adds `pythonpath = ../secubox-annuaire` to `pytest.ini`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-release && ../../.venv/bin/pytest tests/test_boxapply.py -q` (after Task 9 wires pythonpath; if running standalone now, add `sys.path` to the test).
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-release/release/boxapply.py packages/secubox-release/tests/test_boxapply.py
git commit -m "feat(release): box actuator — 4R ring sources drop-in (apt-fail rolls back, never bricks) (ref release-rings)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Task 6: secubox-releasectl — CLI (center/repo/box)

**Files:**
- Create: `packages/secubox-release/sbin/secubox-releasectl`, `sbin/secubox-release-repo`
- Test: `packages/secubox-release/tests/test_releasectl.py`

**Interfaces:** model on `sbx-centersctl`/`secubox-assistctl`. Env: `ANNUAIRE_KEY_PATH` (default `/etc/secubox/secrets/annuaire/node.key`), `ANNUAIRE_JOURNAL`, `ANNUAIRE_LIB`, `RELEASE_LIB`. `DRYRUN=1` writes nothing. Subcommands: `publish --artifacts <json> --notes …` (mints `evo_id="evo-"+token_hex(8)`), `promote <evo_id>`, `demote <evo_id>`, `assign <box_did> <ring>`, `list` (`{evolutions:[{evo_id,ring}], }`), `sync-repo` (host: for each evolution, run the reprepro copies for its current ring — `release.repo.plan_promote`), `apply` (box: resolve `box_ring(entries, self_did, self_did)`, run `boxapply.apply_4r` with a real apt-update fn). All mutating verbs wrapped `try/except ValueError as exc: _die(str(exc))`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-release/tests/test_releasectl.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, subprocess, sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-releasectl")
ANN = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
REL = str(Path(__file__).resolve().parent.parent)


def _env(tmp_path):
    key = tmp_path / "node.key"; key.write_text("11" * 32)
    env = dict(os.environ)
    env.update(ANNUAIRE_KEY_PATH=str(key), ANNUAIRE_JOURNAL=str(tmp_path / "j.db"),
               ANNUAIRE_LIB=ANN, RELEASE_LIB=REL,
               PYTHONPATH=os.pathsep.join([ANN, REL, env.get("PYTHONPATH", "")]))
    return env


def test_publish_then_list(tmp_path):
    env = _env(tmp_path)
    arts = json.dumps([{"kind": "deb", "name": "secubox-dpi", "version": "1.2.3",
                        "hash": "ab", "arch": "arm64"}])
    r = subprocess.run([sys.executable, CTL, "publish", "--artifacts", arts,
                        "--notes", "x"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout).get("evo_id")
    r2 = subprocess.run([sys.executable, CTL, "list"], env=env, capture_output=True, text=True)
    evos = json.loads(r2.stdout)["evolutions"]
    assert evos and evos[0]["ring"] == "draft"


def test_dryrun_writes_nothing(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    arts = json.dumps([{"kind": "deb", "name": "x", "version": "1", "hash": "ab", "arch": "arm64"}])
    r = subprocess.run([sys.executable, CTL, "publish", "--artifacts", arts, "--notes", "n"],
                       env=env, capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True
    r2 = subprocess.run([sys.executable, CTL, "list"], env=env, capture_output=True, text=True)
    assert json.loads(r2.stdout)["evolutions"] == []
```

- [ ] **Step 2-4:** Implement `sbin/secubox-releasectl` (mirror `secubox-assistctl`: `_key()`/`_journal()`/`_self_did()`/`_now()`/`_dry()`/`_die()`, argparse subparsers; `publish` calls `verbs.release_publish`; `promote`/`demote`/`assign` call the grant-gated verbs with `self_did=_self_did(_key())`; `list` prints `[{evo_id, ring: releases.current_ring(...)}]`; `sync-repo` iterates evolutions and execs `release.repo.plan_promote` argv via `subprocess.run(shell=False)`; `apply` resolves `box_ring` and runs `boxapply.apply_4r(ring, boxapply.RING_LIST_PATH, apt_update_fn=lambda p: subprocess.run(["apt-get","-o",f"Dir::Etc::sourcelist={p}","-o","Dir::Etc::sourceparts=-","update"]).returncode==0)`). `chmod +x` both sbin files. Make `sbin/secubox-release-repo` a thin wrapper calling the ctl's `sync-repo`. Run `cd packages/secubox-release && ../../.venv/bin/pytest tests/test_releasectl.py -q` red→green.

- [ ] **Step 5: Commit** `feat(release): secubox-releasectl (publish/promote/demote/assign/list/sync-repo/apply, DRYRUN)` + trailer.

---

## Task 7: API — /releases endpoints (reads in-process, writes via ctl)

**Files:**
- Create: `packages/secubox-release/api/__init__.py`, `api/main.py`
- Test: `packages/secubox-release/tests/test_api.py`

**Interfaces:** JWT-gated except `/status`+`/health`. `GET /evolutions` (in-process: each `RELEASE_PUBLISH` evo + `releases.current_ring`), `GET /box-ring` (`releases.box_ring(entries, self_did, self_did)`), `POST /publish`, `POST /promote` (`{evo_id}`), `POST /demote`, `POST /assign` (`{box_did, ring}`) → shell to `secubox-releasectl`. Mirror the socle `_ctl`/`_entries`/`_self_did`/`require_jwt` pattern.

- [ ] **Steps:** TDD — `test_api.py`: `/status` public 200; `/evolutions` without JWT → 401/403. Implement mirroring `secubox-assist/api/main.py`. Red→green `cd packages/secubox-release && ../../.venv/bin/pytest tests/test_api.py -q`. Commit `feat(release): /releases API (JWT, reads in-process, writes via ctl)` + trailer.

---

## Task 8: /releases panel + menu + vhost

**Files:**
- Create: `packages/secubox-release/www/releases/index.html`, `menu.d/590-releases.json`, `nginx/releases.conf`
- Test: `packages/secubox-release/tests/test_menu.py`

**Interfaces:** hybrid-dark, `sbx_token`, `/shared/sidebar.js`, event delegation (no inline `on*=`), all API data via `textContent`. Evolution×ring matrix with promote/demote buttons; box×ring assign; `notify()` feedback like the assist panel. `menu.d/590-releases.json` uses `name`/`category` (category `mesh` or `root`), matching the hub schema.

- [ ] **Steps:** `test_menu.py` asserts valid menu JSON with `name`+`category`-in-valid-set, panel has `sbx_token`+`/shared/sidebar.js`+no `onclick=`+no `innerHTML`, and promote/demote/assign `data-act` hooks. nginx `releases.conf`: `location /releases/ { alias …; }` + `location /api/v1/release/ { rewrite ^/api/v1/release/(.*)$ /$1 break; proxy_pass http://unix:/run/secubox/release.sock; }` (rewrite pattern — the proven one). Red→green. Commit + trailer.

---

## Task 9: packaging — services, sudoers, install, changelog, pytest wiring

**Files:**
- Create: `packages/secubox-release/systemd/secubox-release-api.service`, `sudoers/secubox-release`, `debian/{postinst,prerm,secubox-release.install}`
- Modify: `packages/secubox-release/pytest.ini` (add `pythonpath = ../secubox-annuaire`), `debian/control` (finalize Depends), `packages/secubox-annuaire/debian/changelog` (ship releases.py, bump).
- Test: `packages/secubox-release/tests/test_packaging.py`

**Interfaces:** the API service runs `User=secubox` on `/run/secubox/release.sock` (`RuntimeDirectory=secubox`, `RuntimeDirectoryPreserve=yes`, `NoNewPrivileges=true`). sudoers scoped to `/usr/sbin/secubox-releasectl` ONLY. postinst: enable the API service, reload nginx dropin, and (guarded) `chmod o+x /etc/secubox/secrets` (the ctl signs as secubox — same traversal fix as assist). NEVER chown shared parents. `#DEBHELPER#` alone. The reprepro ring distributions (`draft`/`internal`/`published`) are provisioned on the apt host separately (documented deploy step — the postinst does NOT edit `/data/apt/conf/distributions`, which is repo-host state, not board state).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-release/tests/test_packaging.py — key assertions
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent


def test_sudoers_scoped():
    s = (ROOT / "sudoers" / "secubox-release").read_text()
    assert "/usr/sbin/secubox-releasectl" in s
    assert "NOPASSWD: ALL" not in s


def test_api_unit_non_root_preserve_runtime():
    u = (ROOT / "systemd" / "secubox-release-api.service").read_text()
    assert "User=secubox" in u and "RuntimeDirectoryPreserve=yes" in u


def test_postinst_no_shared_parent_chown():
    p = (ROOT / "debian" / "postinst").read_text()
    for bad in ("chown -R secubox /run/secubox", "chown -R secubox /etc/secubox",
                "chown -R secubox /data/apt"):
        assert bad not in p
```

- [ ] **Steps 2-4:** create the units/sudoers/install/postinst per the interfaces; add `pythonpath = ../secubox-annuaire` to `pytest.ini`; run the FULL package suite `cd packages/secubox-release && ../../.venv/bin/pytest tests/ -q` and `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/ -q`; build both `.deb` (`dpkg-buildpackage -us -uc -b`) and confirm `release/*.py` + `annuaire/releases.py` ship. Bump `secubox-annuaire` changelog.

- [ ] **Step 5: Commit** `build(release): packaging — API unit, scoped sudoers, install, secrets traversal; annuaire ships releases.py` + trailer.

---

## Self-Review

**1. Spec coverage:** RELEASE_* ops+models → T1. Pure resolver (current_ring, box_ring sovereignty, evolutions_in_ring, has_release_grant) → T2. Grant-gated one-step verbs → T3. reprepro-copy actuator (arm64 guard, op-gated argv) → T4. Box 4R ring switch (apt-fail rolls back) → T5. CLI (publish/promote/demote/assign/list/sync-repo/apply, DRYRUN) → T6. API (JWT, delegate to ctl) → T7. Panel matrices → T8. Packaging (non-root unit, scoped sudoers, secrets traversal, no shared-parent chown, GPG untouched) → T9. ✅
Every CSPN invariant maps: grant-gate (T3 verbs + T2 has_release_grant), sovereignty (T2 box_ring filters granted centers), one-step-only (T3 next/prev_ring), never-amd64-only (T4 plan_promote), 4R fail-safe (T5 apply_4r), no-privileged-in-process (T7 delegate + T9 sudoers), no shared-parent chown (T9 test), GPG end-to-end (reprepro re-signs; plan never bypasses).

**2. Placeholder scan:** T6/T7/T8/T9 use compressed steps that mirror the shipped `secubox-assist` ctl/API/panel/packaging patterns verbatim — the novel logic (T1-T5) carries complete code. Flag to implementer: follow the `secubox-assist` files as the template.

**3. Type consistency:** `RINGS`, `current_ring/next_ring/prev_ring/box_ring/has_release_grant` identical across T2/T3/T6/T7. `Evolution.artifacts=[Artifact]` consumed as dicts by T4 `plan_promote`/T6. `copy_argv(from,to,pkgs)` / `apply_4r(ring, path, apt_update_fn)` consistent T4/T5↔T6. Grant reuse: `active_grants(entries, self_did)` + `capability="release"` throughout.

**Cross-task note for the controller:** the reprepro ring distributions (`draft`/`internal`/`published`) must be added to `/data/apt/conf/distributions` on the apt host once, as a deploy step (not in a package postinst — it's repo-host state). Confirm before running `sync-repo` live. This is the one out-of-package prerequisite.
