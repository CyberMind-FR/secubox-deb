<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Annuaire Service Offers + Subscriptions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a service-offer + subscription feature to `secubox-annuaire` so nodes advertise services, remote nodes subscribe (auto or pending approval), and all objects are signed/BLAKE2b-chained log entries.

**Architecture:** Pure verb layer (`annuaire/verbs.py`) with new enums and models (`annuaire/model.py`), wired to six new FastAPI endpoints in `api/main.py`, a "Services" panel appended to `www/annuaire/index.html`, and a `tests/test_services.py` test file covering all authorization paths. Federation uses a `POST /services/pull` endpoint that fetches a remote catalog and calls `ingest_offer()` (which verifies the original provider sig before chaining). The provider pubkey for `ingest_offer` is carried in the `ServiceOffer` object itself (`signer_did` + `pubkey_hex` param) — clean and self-contained.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, Ed25519 via `cryptography`, SQLite WAL, BLAKE2b-256, httpx (already a transitive dep; use `urllib` fallback if absent), pytest.

## Global Constraints

- All files under `packages/secubox-annuaire/`
- SPDX header `# SPDX-License-Identifier: LicenseRef-CMSD-1.0 / Copyright (c) 2026 CyberMind` on every new `.py` file
- Versioning target: `0.1.3-1~bookworm1`
- `debian/compat = 13`, `Standards-Version: 4.6.2`
- ALL 104 existing tests must remain green; add new tests
- Pure verbs (no FastAPI in `verbs.py`)
- No Claude/AI references in commit messages or code
- Mutating API endpoints MUST use `Depends(_require_jwt)`
- Socket Unix: `/run/secubox/annuaire.sock` (no TCP)
- Commit message: `feat(annuaire): service offers + subscription (auto/pending approval) + pull federation`

---

## File Map

| File | Change |
|------|--------|
| `annuaire/model.py` | Add `ApprovalMode`, `SubscriptionState` enums; 6 new `Op` members; `ServiceOffer`, `Subscription` models |
| `annuaire/verbs.py` | Add 6 verb functions + 4 internal helpers |
| `api/main.py` | Add 7 request models + 8 new endpoints |
| `www/annuaire/index.html` | Append Services panel (keep existing panels) |
| `tests/test_services.py` | New test file: ≥ 14 tests covering all authorization paths |
| `debian/changelog` | New entry for 0.1.3 |

---

## Task 1: Model — enums, Op members, ServiceOffer, Subscription

**Files:**
- Modify: `annuaire/model.py`

**Interfaces:**
- Produces: `ApprovalMode`, `SubscriptionState`, `Op.SERVICE_OFFER`, `Op.SERVICE_REVOKE_OFFER`, `Op.SERVICE_SUBSCRIBE`, `Op.SERVICE_APPROVE`, `Op.SERVICE_REJECT`, `Op.SERVICE_REVOKE_SUB`, `ServiceOffer(BaseModel)`, `Subscription(BaseModel)`

- [ ] **Step 1: Write the failing test for model changes**

Create `tests/test_services.py` with just the model imports:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_services.py
Pytest coverage for service offers + subscription feature.
"""
import os
import tempfile

import pytest

from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign, verify
from annuaire.log import Journal
from annuaire.model import (
    ApprovalMode,
    Identity,
    MemberState,
    Op,
    ServiceOffer,
    Subscription,
    SubscriptionState,
    now_rfc3339,
)
from annuaire.verbs import (
    _get_offer,
    _get_offers,
    approve_subscription,
    auto_add,
    ingest_offer,
    invite,
    accept_invite,
    offer_service,
    reject_subscription,
    revoke_offer,
    subscribe,
    subscription_state,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_journal(tmp_path):
    return Journal(str(tmp_path / "test.db"))


def make_member(journal: Journal):
    """Create a MEMBER node: auto_add + invite + accept_invite."""
    # Founder key
    founder_priv, founder_pub = generate_keypair()
    founder_did = did_from_pubkey(founder_pub)

    # Bootstrap founder as MEMBER via auto_add + self-invite trick:
    # 1. Auto-add founder as OBSERVED
    import hashlib
    digest = hashlib.sha256(founder_pub).hexdigest()[:32]
    ident = Identity(
        did=founder_did,
        pubkey=founder_pub.hex(),
        self_cert_digest=digest,
        state=MemberState.OBSERVED,
    )
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    payload["state"] = MemberState.OBSERVED.value
    sig_hex = sign(founder_priv, canonical_bytes(payload))
    ident_with_sig = Identity(**{**full, "sig": sig_hex, "signer_did": founder_did})
    auto_add(journal, ident_with_sig)

    # 2. Promote to MEMBER directly (post MEMBER Identity self-authored)
    ident_member = Identity(
        did=founder_did,
        pubkey=founder_pub.hex(),
        self_cert_digest=digest,
        state=MemberState.MEMBER,
        invited_by=None,
    )
    full_m = ident_member.model_dump()
    payload_m = {k: v for k, v in full_m.items() if k not in ("sig", "signer_did")}
    sig_m = sign(founder_priv, canonical_bytes(payload_m))
    from annuaire.log import Journal as J
    journal.append(
        op=Op.INVITE_ACCEPT,
        payload_type="Identity",
        payload=payload_m,
        author=founder_did,
        sig=sig_m,
        author_pubkey_hex=founder_pub.hex(),
    )
    return founder_priv, founder_pub, founder_did


def make_two_members(journal: Journal):
    """Return (priv_a, pub_a, did_a, priv_b, pub_b, did_b) both MEMBER."""
    priv_a, pub_a, did_a = make_member(journal)

    priv_b, pub_b = generate_keypair()
    did_b = did_from_pubkey(pub_b)
    inv = invite(journal, priv_a, did_a, domain="test")
    accept_invite(journal, priv_b, did_b, inv)

    return priv_a, pub_a, did_a, priv_b, pub_b, did_b


# ---------------------------------------------------------------------------
# Smoke: model constructable
# ---------------------------------------------------------------------------

def test_model_service_offer_constructable():
    _, pub, did = generate_keypair()[0], *generate_keypair()
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    offer = ServiceOffer(
        service_id="abc123",
        provider=did,
        name="MyAPI",
        kind="api",
        endpoint="/api/v1/foo",
        scope={"isolation_domain": "fr-chambery"},
        approval_mode=ApprovalMode.AUTO,
        description="test service",
        created_at=now_rfc3339(),
        sig=None,
        signer_did=None,
    )
    assert offer.service_id == "abc123"
    assert offer.approval_mode == ApprovalMode.AUTO


def test_model_subscription_constructable():
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    sub = Subscription(
        subscription_id="sub123",
        subscriber=did,
        service_id="abc123",
        requested_at=now_rfc3339(),
        sig=None,
        signer_did=None,
    )
    assert sub.subscription_id == "sub123"


def test_op_enum_has_service_members():
    assert Op.SERVICE_OFFER.value == "service_offer"
    assert Op.SERVICE_REVOKE_OFFER.value == "service_revoke_offer"
    assert Op.SERVICE_SUBSCRIBE.value == "service_subscribe"
    assert Op.SERVICE_APPROVE.value == "service_approve"
    assert Op.SERVICE_REJECT.value == "service_reject"
    assert Op.SERVICE_REVOKE_SUB.value == "service_revoke_sub"
    assert ApprovalMode.AUTO.value == "auto"
    assert ApprovalMode.PENDING.value == "pending"
    assert SubscriptionState.APPROVED.value == "approved"
    assert SubscriptionState.PENDING.value == "pending"
```

- [ ] **Step 2: Run test to verify it fails (ImportError expected)**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/test_services.py -q 2>&1 | head -20
```

Expected: `ImportError: cannot import name 'ApprovalMode'` (or similar)

- [ ] **Step 3: Add enums and models to `annuaire/model.py`**

After the existing `RevocationScope` enum (line ~87) and before `JuridictionTag`, add:

```python
class ApprovalMode(str, Enum):
    """Whether a service subscription is approved automatically or requires provider action."""
    AUTO    = "auto"
    PENDING = "pending"


class SubscriptionState(str, Enum):
    """Derived state of a Subscription (computed from the log, never stored)."""
    PENDING  = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED  = "revoked"
```

Then add to the `Op` enum, after `NAME_REVOKE`:

```python
    SERVICE_OFFER        = "service_offer"
    SERVICE_REVOKE_OFFER = "service_revoke_offer"
    SERVICE_SUBSCRIBE    = "service_subscribe"
    SERVICE_APPROVE      = "service_approve"
    SERVICE_REJECT       = "service_reject"
    SERVICE_REVOKE_SUB   = "service_revoke_sub"
```

Then after `WitnessAttest` class, add:

```python
# ---------------------------------------------------------------------------
# ServiceOffer — a provider advertising a service to the trust graph
# ---------------------------------------------------------------------------

class ServiceOffer(BaseModel):
    """A signed offer of a service by a provider node.

    Self-certifying: authored by the provider (entry.author == provider).
    The sig covers canonical_bytes(payload_without_sig).
    approval_mode=AUTO: subscription is APPROVED immediately (derived).
    approval_mode=PENDING: requires an explicit SERVICE_APPROVE from the provider.
    """
    model_config = ConfigDict(extra="forbid")

    service_id:    str = Field(..., description="random hex id")
    provider:      str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    name:          str
    kind:          str = Field(..., description="e.g. 'module', 'api', 'mirror'")
    endpoint:      str = Field(..., description="mesh URL or local path")
    scope:         Dict[str, Any] = Field(default_factory=dict)
    approval_mode: ApprovalMode = ApprovalMode.AUTO
    description:   str = ""
    created_at:    str = Field(default_factory=now_rfc3339)
    sig:           Optional[str] = Field(
        default=None,
        description="Ed25519 sig over canonical_bytes(payload_without_sig)",
    )
    signer_did:    Optional[str] = None


# ---------------------------------------------------------------------------
# Subscription — a subscriber requesting access to a ServiceOffer
# ---------------------------------------------------------------------------

class Subscription(BaseModel):
    """A signed subscription request from a subscriber node.

    Self-certifying: authored by the subscriber (entry.author == subscriber).
    State is DERIVED from the log — see subscription_state() in verbs.py.
    """
    model_config = ConfigDict(extra="forbid")

    subscription_id: str = Field(..., description="random hex id")
    subscriber:      str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    service_id:      str
    requested_at:    str = Field(default_factory=now_rfc3339)
    sig:             Optional[str] = None
    signer_did:      Optional[str] = None
```

Also update the imports at the top of `annuaire/model.py` — `Dict` and `Any` are already imported, nothing new needed.

- [ ] **Step 4: Run test to verify model smoke tests pass**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/test_services.py::test_model_service_offer_constructable tests/test_services.py::test_model_subscription_constructable tests/test_services.py::test_op_enum_has_service_members -v
```

Expected: 3 passed. The verb-import tests will still fail (that's Task 2).

- [ ] **Step 5: Verify all 104 original tests still pass**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/test_crypto.py tests/test_log.py tests/test_model.py tests/test_resolver.py tests/test_verbs.py -q
```

Expected: `104 passed`

- [ ] **Step 6: Commit**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
git add annuaire/model.py tests/test_services.py
git commit -m "feat(annuaire): add ApprovalMode, SubscriptionState, service Op members, ServiceOffer, Subscription models"
```

---

## Task 2: Verbs — offer_service, revoke_offer, subscribe, approve/reject, subscription_state, helpers, ingest_offer

**Files:**
- Modify: `annuaire/verbs.py`

**Interfaces:**
- Consumes: `ServiceOffer`, `Subscription`, `Op.SERVICE_*`, `ApprovalMode`, `SubscriptionState` from Task 1; `_is_non_revoked_member`, `_rand_hex`, `_get_inviter_pubkey` (already in verbs.py)
- Produces:
  - `offer_service(journal, provider_priv, provider_did, *, name, kind, endpoint, scope=None, approval_mode="auto", description="") -> ServiceOffer`
  - `revoke_offer(journal, provider_priv, provider_did, service_id) -> None`
  - `subscribe(journal, subscriber_priv, subscriber_did, service_id) -> Subscription`
  - `approve_subscription(journal, approver_priv, approver_did, subscription_id) -> None`
  - `reject_subscription(journal, rejecter_priv, rejecter_did, subscription_id) -> None`
  - `subscription_state(journal, subscription_id) -> SubscriptionState`
  - `_get_offers(journal) -> List[Dict]`
  - `_get_offer(journal, service_id) -> Optional[Dict]`
  - `ingest_offer(journal, offer: ServiceOffer, provider_pubkey_hex: str) -> ServiceOffer`

- [ ] **Step 1: Add the failing verb tests to `tests/test_services.py`**

Append these test functions to `tests/test_services.py` (after the smoke tests):

```python
# ---------------------------------------------------------------------------
# Verb tests
# ---------------------------------------------------------------------------

def test_offer_service_appears_in_catalog(tmp_journal):
    """offer_service → appears in _get_offers and catalog is non-empty."""
    priv, pub, did = make_member(tmp_journal)
    offer = offer_service(
        tmp_journal, priv, did,
        name="TestAPI", kind="api", endpoint="/api/v1/test",
        scope={"isolation_domain": "fr-test"},
        approval_mode="auto", description="A test service",
    )
    assert offer.service_id
    catalog = _get_offers(tmp_journal)
    assert any(o["service_id"] == offer.service_id for o in catalog)


def test_subscribe_auto_offer_is_approved(tmp_journal):
    """subscribe to an AUTO offer → subscription_state == APPROVED (no provider action)."""
    priv_a, pub_a, did_a, priv_b, pub_b, did_b = make_two_members(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x",
                          approval_mode="auto")
    sub = subscribe(tmp_journal, priv_b, did_b, offer.service_id)
    assert subscription_state(tmp_journal, sub.subscription_id) == SubscriptionState.APPROVED


def test_subscribe_pending_offer_stays_pending_then_approved(tmp_journal):
    """subscribe to PENDING offer → PENDING; provider approve → APPROVED."""
    priv_a, pub_a, did_a, priv_b, pub_b, did_b = make_two_members(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x",
                          approval_mode="pending")
    sub = subscribe(tmp_journal, priv_b, did_b, offer.service_id)
    assert subscription_state(tmp_journal, sub.subscription_id) == SubscriptionState.PENDING

    approve_subscription(tmp_journal, priv_a, did_a, sub.subscription_id)
    assert subscription_state(tmp_journal, sub.subscription_id) == SubscriptionState.APPROVED


def test_subscribe_pending_offer_rejected(tmp_journal):
    """provider reject → REJECTED."""
    priv_a, pub_a, did_a, priv_b, pub_b, did_b = make_two_members(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x",
                          approval_mode="pending")
    sub = subscribe(tmp_journal, priv_b, did_b, offer.service_id)
    reject_subscription(tmp_journal, priv_a, did_a, sub.subscription_id)
    assert subscription_state(tmp_journal, sub.subscription_id) == SubscriptionState.REJECTED


def test_approve_subscription_non_provider_rejected(tmp_journal):
    """A non-provider calling approve_subscription → PermissionError."""
    priv_a, pub_a, did_a, priv_b, pub_b, did_b = make_two_members(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x",
                          approval_mode="pending")
    sub = subscribe(tmp_journal, priv_b, did_b, offer.service_id)
    # did_b is the subscriber, not the provider — must be rejected
    with pytest.raises(PermissionError):
        approve_subscription(tmp_journal, priv_b, did_b, sub.subscription_id)


def test_revoke_offer_by_provider_drops_from_catalog(tmp_journal):
    """revoke_offer by provider → offer drops from _get_offers, new subscribe fails."""
    priv_a, pub_a, did_a, priv_b, pub_b, did_b = make_two_members(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x")
    revoke_offer(tmp_journal, priv_a, did_a, offer.service_id)

    catalog = _get_offers(tmp_journal)
    assert not any(o["service_id"] == offer.service_id for o in catalog)

    with pytest.raises((ValueError, PermissionError)):
        subscribe(tmp_journal, priv_b, did_b, offer.service_id)


def test_revoke_offer_by_non_provider_rejected(tmp_journal):
    """revoke_offer by non-provider → PermissionError."""
    priv_a, pub_a, did_a, priv_b, pub_b, did_b = make_two_members(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x")
    with pytest.raises(PermissionError):
        revoke_offer(tmp_journal, priv_b, did_b, offer.service_id)


def test_subscribe_by_non_member_rejected(tmp_journal):
    """subscribe by an OBSERVED (non-MEMBER) node → rejected (PermissionError or ValueError)."""
    priv_a, pub_a, did_a = make_member(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x")

    # Create an OBSERVED node (not a member)
    priv_obs, pub_obs = generate_keypair()
    did_obs = did_from_pubkey(pub_obs)
    import hashlib
    digest = hashlib.sha256(pub_obs).hexdigest()[:32]
    obs_ident = Identity(
        did=did_obs, pubkey=pub_obs.hex(), self_cert_digest=digest,
        state=MemberState.OBSERVED,
    )
    full = obs_ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    payload["state"] = MemberState.OBSERVED.value
    sig_hex = sign(priv_obs, canonical_bytes(payload))
    obs_ident_signed = Identity(**{**full, "sig": sig_hex, "signer_did": did_obs})
    auto_add(tmp_journal, obs_ident_signed)

    with pytest.raises((PermissionError, ValueError)):
        subscribe(tmp_journal, priv_obs, did_obs, offer.service_id)


def test_ingest_offer_valid_sig_accepted(tmp_journal):
    """ingest_offer with a VALID provider sig → ingested into catalog."""
    priv_a, pub_a, did_a = make_member(tmp_journal)

    # Build a signed offer manually (simulates a remote provider)
    from annuaire.model import ServiceOffer
    import os
    service_id = os.urandom(16).hex()
    offer_payload = {
        "service_id": service_id,
        "provider": did_a,
        "name": "RemoteSvc",
        "kind": "mirror",
        "endpoint": "https://remote.example/api",
        "scope": {},
        "approval_mode": ApprovalMode.AUTO.value,
        "description": "ingested from remote",
        "created_at": now_rfc3339(),
    }
    sig_hex = sign(priv_a, canonical_bytes(offer_payload))
    remote_offer = ServiceOffer(
        **offer_payload, sig=sig_hex, signer_did=did_a
    )

    # Ingest with the provider's pubkey
    result = ingest_offer(tmp_journal, remote_offer, provider_pubkey_hex=pub_a.hex())
    catalog = _get_offers(tmp_journal)
    assert any(o["service_id"] == service_id for o in catalog)


def test_ingest_offer_forged_sig_rejected(tmp_journal):
    """ingest_offer with a TAMPERED/forged sig → ValueError, not in catalog before."""
    priv_a, pub_a, did_a = make_member(tmp_journal)
    priv_evil, pub_evil = generate_keypair()

    import os
    from annuaire.model import ServiceOffer
    service_id = os.urandom(16).hex()
    offer_payload = {
        "service_id": service_id,
        "provider": did_a,
        "name": "EvilSvc",
        "kind": "mirror",
        "endpoint": "https://evil.example/api",
        "scope": {},
        "approval_mode": ApprovalMode.AUTO.value,
        "description": "forged",
        "created_at": now_rfc3339(),
    }
    # Sign with evil key instead of provider's key
    forged_sig = sign(priv_evil, canonical_bytes(offer_payload))
    forged_offer = ServiceOffer(**offer_payload, sig=forged_sig, signer_did=did_a)

    with pytest.raises(ValueError):
        ingest_offer(tmp_journal, forged_offer, provider_pubkey_hex=pub_a.hex())

    catalog = _get_offers(tmp_journal)
    assert not any(o["service_id"] == service_id for o in catalog)


def test_approve_entry_not_by_provider_does_not_approve(tmp_journal):
    """Defense in depth: a SERVICE_APPROVE entry NOT authored by the provider
    must NOT change the subscription state to APPROVED."""
    priv_a, pub_a, did_a, priv_b, pub_b, did_b = make_two_members(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x",
                          approval_mode="pending")
    sub = subscribe(tmp_journal, priv_b, did_b, offer.service_id)

    # Inject a forged SERVICE_APPROVE authored by subscriber (not provider)
    forged_payload = {
        "subscription_id": sub.subscription_id,
        "approver": did_b,  # subscriber forging an approval
        "approved_at": now_rfc3339(),
    }
    forged_sig = sign(priv_b, canonical_bytes(forged_payload))
    tmp_journal.append(
        op=Op.SERVICE_APPROVE,
        payload_type="ServiceApprove",
        payload=forged_payload,
        author=did_b,
        sig=forged_sig,
        author_pubkey_hex=pub_b.hex(),
    )

    # Must still be PENDING (forged approve not honored)
    assert subscription_state(tmp_journal, sub.subscription_id) == SubscriptionState.PENDING


def test_revoke_subscription_by_subscriber(tmp_journal):
    """Subscriber may self-revoke their own subscription."""
    priv_a, pub_a, did_a, priv_b, pub_b, did_b = make_two_members(tmp_journal)
    offer = offer_service(tmp_journal, priv_a, did_a,
                          name="Svc", kind="module", endpoint="/x",
                          approval_mode="auto")
    sub = subscribe(tmp_journal, priv_b, did_b, offer.service_id)
    assert subscription_state(tmp_journal, sub.subscription_id) == SubscriptionState.APPROVED

    # Import revoke_subscription for self-revoke
    from annuaire.verbs import revoke_subscription
    revoke_subscription(tmp_journal, priv_b, did_b, sub.subscription_id)
    assert subscription_state(tmp_journal, sub.subscription_id) == SubscriptionState.REVOKED
```

- [ ] **Step 2: Run test to verify failures are ImportError/AttributeError**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/test_services.py -q 2>&1 | head -20
```

Expected: failures with `ImportError: cannot import name 'offer_service'` (or similar)

- [ ] **Step 3: Add helpers and verb functions to `annuaire/verbs.py`**

Update the imports at the top of `annuaire/verbs.py` to add the new model names:

```python
from .model import (
    GENESIS_HASH,
    ApprovalMode,
    Identity,
    Invitation,
    MemberState,
    Op,
    Proposal,
    ProposalType,
    QuorumRule,
    RevocationNotice,
    RevocationScope,
    ServiceOffer,
    Subscription,
    SubscriptionState,
    now_rfc3339,
)
```

Then append to the end of `annuaire/verbs.py` (after the `emancipate` function):

```python
# ---------------------------------------------------------------------------
# Service catalog helpers (internal)
# ---------------------------------------------------------------------------

def _get_offers(journal: Journal) -> List[Dict]:
    """Return list of non-revoked ServiceOffer payloads from self-authored entries.

    Self-authoring rule: entry.author must equal offer's provider field.
    A SERVICE_REVOKE_OFFER for a service_id removes it from the catalog.
    """
    offers: Dict[str, Dict] = {}
    revoked_ids: set = set()

    for entry in journal.iter_entries():
        if entry.op == Op.SERVICE_OFFER and entry.payload_type == "ServiceOffer":
            payload = entry.payload
            sid = payload.get("service_id")
            provider = payload.get("provider")
            # Self-authoring: only count if author == provider
            if sid and provider and entry.author == provider:
                offers[sid] = payload
        elif entry.op == Op.SERVICE_REVOKE_OFFER and entry.payload_type == "ServiceRevoke":
            sid = entry.payload.get("service_id")
            provider = entry.payload.get("provider")
            # Only the provider may revoke (self-authored)
            if sid and provider and entry.author == provider:
                revoked_ids.add(sid)

    return [v for k, v in offers.items() if k not in revoked_ids]


def _get_offer(journal: Journal, service_id: str) -> Optional[Dict]:
    """Return the non-revoked ServiceOffer payload for service_id, or None."""
    for offer in _get_offers(journal):
        if offer.get("service_id") == service_id:
            return offer
    return None


def _get_subscription(journal: Journal, subscription_id: str) -> Optional[Dict]:
    """Return the Subscription payload for subscription_id, or None.

    Only returns self-authored subscriptions (entry.author == subscriber).
    """
    for entry in journal.iter_entries():
        if (entry.op == Op.SERVICE_SUBSCRIBE
                and entry.payload_type == "Subscription"):
            payload = entry.payload
            if (payload.get("subscription_id") == subscription_id
                    and entry.author == payload.get("subscriber")):
                return payload
    return None


def _get_provider_pubkey(journal: Journal, provider_did: str) -> Optional[str]:
    """Return the pubkey hex for a provider from their latest Identity entry."""
    return _get_inviter_pubkey(journal, provider_did)


# ---------------------------------------------------------------------------
# Public verbs — services
# ---------------------------------------------------------------------------

def offer_service(
    journal: Journal,
    provider_priv: bytes,
    provider_did: str,
    *,
    name: str,
    kind: str,
    endpoint: str,
    scope: Optional[Dict] = None,
    approval_mode: str = "auto",
    description: str = "",
) -> ServiceOffer:
    """POST a signed ServiceOffer to the catalog.

    The provider must be a non-revoked MEMBER.
    The offer is self-authored (author == provider).
    approval_mode=auto: subscriptions auto-approved (derived, no entry needed).
    approval_mode=pending: subscriptions need explicit SERVICE_APPROVE.

    Args:
        journal: append-only Journal.
        provider_priv: 32-byte raw Ed25519 private key of the provider.
        provider_did: provider's did:plc.
        name: human-readable service name.
        kind: service category ("module", "api", "mirror", etc.).
        endpoint: URL or path where the service is reached.
        scope: optional dict of service scope (e.g. {"isolation_domain": "..."}).
        approval_mode: "auto" or "pending" (default "auto").
        description: optional description string.

    Returns:
        The signed ServiceOffer.

    Raises:
        PermissionError: if the provider is not a non-revoked MEMBER.
        ValueError: if approval_mode is invalid.
    """
    if not _is_non_revoked_member(journal, provider_did):
        raise PermissionError(
            f"offer_service: {provider_did} is not a non-revoked MEMBER"
        )

    try:
        am = ApprovalMode(approval_mode)
    except ValueError:
        raise ValueError(
            f"offer_service: invalid approval_mode {approval_mode!r} "
            "(must be 'auto' or 'pending')"
        )

    service_id = _rand_hex(16)
    offer = ServiceOffer(
        service_id=service_id,
        provider=provider_did,
        name=name,
        kind=kind,
        endpoint=endpoint,
        scope=scope or {},
        approval_mode=am,
        description=description,
        created_at=now_rfc3339(),
    )
    full = offer.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(provider_priv, canonical_bytes(payload))

    provider_pubkey = _get_provider_pubkey(journal, provider_did)
    journal.append(
        op=Op.SERVICE_OFFER,
        payload_type="ServiceOffer",
        payload=payload,
        author=provider_did,
        sig=sig_hex,
        author_pubkey_hex=provider_pubkey,
    )

    return ServiceOffer(**{**payload, "sig": sig_hex, "signer_did": provider_did})


def revoke_offer(
    journal: Journal,
    provider_priv: bytes,
    provider_did: str,
    service_id: str,
) -> None:
    """Revoke a ServiceOffer. Only the offer's provider may call this.

    Args:
        journal: append-only Journal.
        provider_priv: 32-byte raw Ed25519 private key of the provider.
        provider_did: the caller's did:plc.
        service_id: the service_id of the offer to revoke.

    Raises:
        PermissionError: if provider_did is not the offer's provider, or offer not found.
    """
    offer = _get_offer(journal, service_id)
    if offer is None:
        raise PermissionError(f"revoke_offer: service_id {service_id!r} not found or already revoked")
    if offer.get("provider") != provider_did:
        raise PermissionError(
            f"revoke_offer: {provider_did} is not the provider of {service_id}"
        )

    revoke_payload = {
        "service_id": service_id,
        "provider": provider_did,
        "revoked_at": now_rfc3339(),
    }
    sig_hex = sign(provider_priv, canonical_bytes(revoke_payload))
    provider_pubkey = _get_provider_pubkey(journal, provider_did)
    journal.append(
        op=Op.SERVICE_REVOKE_OFFER,
        payload_type="ServiceRevoke",
        payload=revoke_payload,
        author=provider_did,
        sig=sig_hex,
        author_pubkey_hex=provider_pubkey,
    )


def subscribe(
    journal: Journal,
    subscriber_priv: bytes,
    subscriber_did: str,
    service_id: str,
) -> Subscription:
    """Subscribe to a service offer.

    The subscriber must be a non-revoked MEMBER.
    The offer must exist and not be revoked.
    The subscription is self-authored (author == subscriber).

    Args:
        journal: append-only Journal.
        subscriber_priv: 32-byte raw Ed25519 private key of the subscriber.
        subscriber_did: subscriber's did:plc.
        service_id: the service_id to subscribe to.

    Returns:
        The signed Subscription.

    Raises:
        PermissionError: if the subscriber is not a non-revoked MEMBER.
        ValueError: if the service_id is not found or revoked.
    """
    if not _is_non_revoked_member(journal, subscriber_did):
        raise PermissionError(
            f"subscribe: {subscriber_did} is not a non-revoked MEMBER"
        )

    offer = _get_offer(journal, service_id)
    if offer is None:
        raise ValueError(
            f"subscribe: service_id {service_id!r} not found or revoked"
        )

    subscription_id = _rand_hex(16)
    sub = Subscription(
        subscription_id=subscription_id,
        subscriber=subscriber_did,
        service_id=service_id,
        requested_at=now_rfc3339(),
    )
    full = sub.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(subscriber_priv, canonical_bytes(payload))

    subscriber_pubkey = _get_inviter_pubkey(journal, subscriber_did)
    journal.append(
        op=Op.SERVICE_SUBSCRIBE,
        payload_type="Subscription",
        payload=payload,
        author=subscriber_did,
        sig=sig_hex,
        author_pubkey_hex=subscriber_pubkey,
    )

    return Subscription(**{**payload, "sig": sig_hex, "signer_did": subscriber_did})


def approve_subscription(
    journal: Journal,
    approver_priv: bytes,
    approver_did: str,
    subscription_id: str,
) -> None:
    """Approve a subscription. Only the offer's provider may call this.

    Resolves subscription → service_id → offer.provider.
    If approver_did != offer.provider → PermissionError.

    Args:
        journal: append-only Journal.
        approver_priv: 32-byte raw Ed25519 private key of the approver.
        approver_did: the caller's did:plc (must be the offer's provider).
        subscription_id: the subscription_id to approve.

    Raises:
        PermissionError: if approver_did is not the offer's provider.
        ValueError: if subscription or offer not found.
    """
    sub_payload = _get_subscription(journal, subscription_id)
    if sub_payload is None:
        raise ValueError(f"approve_subscription: subscription {subscription_id!r} not found")

    service_id = sub_payload.get("service_id")
    offer = _get_offer(journal, service_id)
    if offer is None:
        raise ValueError(f"approve_subscription: service {service_id!r} not found or revoked")

    if offer.get("provider") != approver_did:
        raise PermissionError(
            f"approve_subscription: {approver_did} is not the provider of service {service_id}"
        )

    approve_payload = {
        "subscription_id": subscription_id,
        "approver": approver_did,
        "approved_at": now_rfc3339(),
    }
    sig_hex = sign(approver_priv, canonical_bytes(approve_payload))
    approver_pubkey = _get_provider_pubkey(journal, approver_did)
    journal.append(
        op=Op.SERVICE_APPROVE,
        payload_type="ServiceApprove",
        payload=approve_payload,
        author=approver_did,
        sig=sig_hex,
        author_pubkey_hex=approver_pubkey,
    )


def reject_subscription(
    journal: Journal,
    rejecter_priv: bytes,
    rejecter_did: str,
    subscription_id: str,
) -> None:
    """Reject a subscription. Only the offer's provider may call this.

    Args:
        journal: append-only Journal.
        rejecter_priv: 32-byte raw Ed25519 private key of the rejecter.
        rejecter_did: the caller's did:plc (must be the offer's provider).
        subscription_id: the subscription_id to reject.

    Raises:
        PermissionError: if rejecter_did is not the offer's provider.
        ValueError: if subscription or offer not found.
    """
    sub_payload = _get_subscription(journal, subscription_id)
    if sub_payload is None:
        raise ValueError(f"reject_subscription: subscription {subscription_id!r} not found")

    service_id = sub_payload.get("service_id")
    offer = _get_offer(journal, service_id)
    if offer is None:
        raise ValueError(f"reject_subscription: service {service_id!r} not found or revoked")

    if offer.get("provider") != rejecter_did:
        raise PermissionError(
            f"reject_subscription: {rejecter_did} is not the provider of service {service_id}"
        )

    reject_payload = {
        "subscription_id": subscription_id,
        "rejecter": rejecter_did,
        "rejected_at": now_rfc3339(),
    }
    sig_hex = sign(rejecter_priv, canonical_bytes(reject_payload))
    rejecter_pubkey = _get_provider_pubkey(journal, rejecter_did)
    journal.append(
        op=Op.SERVICE_REJECT,
        payload_type="ServiceReject",
        payload=reject_payload,
        author=rejecter_did,
        sig=sig_hex,
        author_pubkey_hex=rejecter_pubkey,
    )


def revoke_subscription(
    journal: Journal,
    revoker_priv: bytes,
    revoker_did: str,
    subscription_id: str,
) -> None:
    """Self-revoke a subscription. Only the subscriber may call this.

    Args:
        journal: append-only Journal.
        revoker_priv: 32-byte raw Ed25519 private key of the subscriber.
        revoker_did: the subscriber's did:plc.
        subscription_id: the subscription_id to revoke.

    Raises:
        PermissionError: if revoker_did is not the subscription's subscriber.
        ValueError: if subscription not found.
    """
    sub_payload = _get_subscription(journal, subscription_id)
    if sub_payload is None:
        raise ValueError(f"revoke_subscription: subscription {subscription_id!r} not found")

    if sub_payload.get("subscriber") != revoker_did:
        raise PermissionError(
            f"revoke_subscription: {revoker_did} is not the subscriber of {subscription_id}"
        )

    revoke_sub_payload = {
        "subscription_id": subscription_id,
        "subscriber": revoker_did,
        "revoked_at": now_rfc3339(),
    }
    sig_hex = sign(revoker_priv, canonical_bytes(revoke_sub_payload))
    subscriber_pubkey = _get_inviter_pubkey(journal, revoker_did)
    journal.append(
        op=Op.SERVICE_REVOKE_SUB,
        payload_type="ServiceRevokeSub",
        payload=revoke_sub_payload,
        author=revoker_did,
        sig=sig_hex,
        author_pubkey_hex=subscriber_pubkey,
    )


def subscription_state(journal: Journal, subscription_id: str) -> SubscriptionState:
    """Derive the state of a subscription from the log.

    State machine (LAST matching event wins for approve/reject; revoke wins over all):
      1. REVOKED  — if a self-authored SERVICE_REVOKE_SUB by the subscriber exists.
      2. REJECTED — if a provider-authored SERVICE_REJECT exists (author == provider).
      3. APPROVED — if the offer.approval_mode == AUTO, OR a provider-authored
                    SERVICE_APPROVE exists (author == provider, defense in depth).
      4. PENDING  — otherwise.

    Defense in depth: an approve/reject entry NOT authored by the offer's provider
    is silently ignored (does not change state).

    Args:
        journal: append-only Journal.
        subscription_id: the subscription to query.

    Returns:
        SubscriptionState enum value.

    Raises:
        ValueError: if subscription not found.
    """
    sub_payload = _get_subscription(journal, subscription_id)
    if sub_payload is None:
        raise ValueError(f"subscription_state: subscription {subscription_id!r} not found")

    service_id = sub_payload.get("service_id")
    subscriber = sub_payload.get("subscriber")

    offer = _get_offer(journal, service_id)
    # Even if offer was revoked after subscription, we still compute state
    # (we need the provider to verify approval authority)
    offer_provider: Optional[str] = None
    offer_mode = ApprovalMode.PENDING  # conservative default if offer gone

    if offer is not None:
        offer_provider = offer.get("provider")
        try:
            offer_mode = ApprovalMode(offer.get("approval_mode", "pending"))
        except ValueError:
            offer_mode = ApprovalMode.PENDING
    else:
        # Offer was revoked; find the original provider from the SERVICE_OFFER entry
        for entry in journal.iter_entries():
            if (entry.op == Op.SERVICE_OFFER
                    and entry.payload_type == "ServiceOffer"
                    and entry.payload.get("service_id") == service_id
                    and entry.author == entry.payload.get("provider")):
                offer_provider = entry.payload.get("provider")
                try:
                    offer_mode = ApprovalMode(entry.payload.get("approval_mode", "pending"))
                except ValueError:
                    offer_mode = ApprovalMode.PENDING
                break

    # Scan all subsequent entries to derive state
    revoked = False
    approved = False
    rejected = False

    for entry in journal.iter_entries():
        # 1. Self-revoke by subscriber
        if (entry.op == Op.SERVICE_REVOKE_SUB
                and entry.payload_type == "ServiceRevokeSub"
                and entry.payload.get("subscription_id") == subscription_id
                and entry.author == subscriber):
            revoked = True

        # 2. Provider reject (defense: author must be the offer's provider)
        if (entry.op == Op.SERVICE_REJECT
                and entry.payload_type == "ServiceReject"
                and entry.payload.get("subscription_id") == subscription_id
                and offer_provider is not None
                and entry.author == offer_provider):
            rejected = True

        # 3. Provider approve (defense: author must be the offer's provider)
        if (entry.op == Op.SERVICE_APPROVE
                and entry.payload_type == "ServiceApprove"
                and entry.payload.get("subscription_id") == subscription_id
                and offer_provider is not None
                and entry.author == offer_provider):
            approved = True

    if revoked:
        return SubscriptionState.REVOKED
    if rejected:
        return SubscriptionState.REJECTED
    if approved or offer_mode == ApprovalMode.AUTO:
        return SubscriptionState.APPROVED
    return SubscriptionState.PENDING


def ingest_offer(
    journal: Journal,
    offer: ServiceOffer,
    provider_pubkey_hex: str,
) -> ServiceOffer:
    """Federation primitive: verify a remote provider's signed offer and ingest it.

    The provider_pubkey_hex is passed explicitly (the peer sends their Identity
    alongside the offer, or it was fetched via GET /identity). This avoids trusting
    the local log to have the remote provider's key.

    Verification:
      1. offer.sig must not be None.
      2. Verify offer.sig against canonical_bytes(payload_without_sig) using provider_pubkey_hex.
      3. offer.signer_did must equal offer.provider (the offer must be self-authored).
      4. Only on success: append to the local journal (op=SERVICE_OFFER, author=provider).

    Args:
        journal: append-only Journal.
        offer: ServiceOffer received from a remote node.
        provider_pubkey_hex: the remote provider's Ed25519 pubkey (hex, 32 bytes = 64 hex chars).

    Returns:
        The ingested ServiceOffer.

    Raises:
        ValueError: if sig is missing, sig verification fails, or signer_did != provider.
    """
    if not offer.sig:
        raise ValueError("ingest_offer: offer has no signature")

    if offer.signer_did != offer.provider:
        raise ValueError(
            f"ingest_offer: offer.signer_did ({offer.signer_did}) "
            f"must equal offer.provider ({offer.provider}) — not self-authored"
        )

    full = offer.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}

    if not verify(provider_pubkey_hex, canonical_bytes(payload), offer.sig):
        raise ValueError("ingest_offer: signature verification failed — offer rejected")

    # Append to local journal preserving the original sig and author
    journal.append(
        op=Op.SERVICE_OFFER,
        payload_type="ServiceOffer",
        payload=payload,
        author=offer.provider,
        sig=offer.sig,
        author_pubkey_hex=provider_pubkey_hex,
    )

    return offer
```

- [ ] **Step 4: Run all service tests**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/test_services.py -v
```

Expected: all tests pass (the `make_member` helper uses INVITE_ACCEPT op which the existing Journal handles fine).

- [ ] **Step 5: Run full test suite — all 104 + new tests green**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/ -q
```

Expected: `11X passed` (104 + new)

- [ ] **Step 6: Commit**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
git add annuaire/verbs.py tests/test_services.py
git commit -m "feat(annuaire): service verb layer — offer_service, subscribe, approve/reject, subscription_state, ingest_offer"
```

---

## Task 3: API — 8 new endpoints

**Files:**
- Modify: `api/main.py`

**Interfaces:**
- Consumes: `offer_service`, `revoke_offer`, `subscribe`, `approve_subscription`, `reject_subscription`, `subscription_state`, `_get_offers`, `_get_subscription`, `ingest_offer` from Task 2; `ServiceOffer` from Task 1
- Produces endpoints:
  - `GET /services` → list offers
  - `POST /service/offer` (auth)
  - `POST /service/{service_id}/revoke` (auth)
  - `POST /service/{service_id}/subscribe` (auth)
  - `GET /subscriptions`
  - `POST /subscription/{subscription_id}/approve` (auth)
  - `POST /subscription/{subscription_id}/reject` (auth)
  - `POST /services/pull` (auth)

- [ ] **Step 1: Write the API smoke test**

Add to `tests/test_services.py`, below existing tests (uses TestClient from fastapi.testclient):

```python
# ---------------------------------------------------------------------------
# API smoke tests (TestClient, no JWT in test mode)
# ---------------------------------------------------------------------------

def test_api_get_services_empty(tmp_path, monkeypatch):
    """GET /services returns an empty list on a fresh journal."""
    from fastapi.testclient import TestClient
    import api.main as am
    db = str(tmp_path / "api_test.db")
    monkeypatch.setenv("ANNUAIRE_DB_PATH", db)
    am._journal = None  # reset singleton
    client = TestClient(am.app)
    r = client.get("/services")
    assert r.status_code == 200
    assert r.json() == []


def test_api_services_round_trip(tmp_path, monkeypatch):
    """POST /service/offer (with priv key) → appears in GET /services."""
    from fastapi.testclient import TestClient
    import api.main as am
    db = str(tmp_path / "api_rt.db")
    monkeypatch.setenv("ANNUAIRE_DB_PATH", db)
    am._journal = None
    client = TestClient(am.app)

    # Bootstrap a MEMBER in the journal
    j = am.get_journal()
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    import hashlib
    digest = hashlib.sha256(pub).hexdigest()[:32]
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=digest, state=MemberState.OBSERVED)
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    payload["state"] = MemberState.OBSERVED.value
    sig_hex = sign(priv, canonical_bytes(payload))
    ident_signed = Identity(**{**full, "sig": sig_hex, "signer_did": did})
    auto_add(j, ident_signed)
    # Promote to MEMBER
    ident_m = Identity(did=did, pubkey=pub.hex(), self_cert_digest=digest, state=MemberState.MEMBER, invited_by=None)
    full_m = ident_m.model_dump()
    payload_m = {k: v for k, v in full_m.items() if k not in ("sig", "signer_did")}
    sig_m = sign(priv, canonical_bytes(payload_m))
    j.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload_m,
              author=did, sig=sig_m, author_pubkey_hex=pub.hex())

    r = client.post("/service/offer", json={
        "provider_did": did,
        "provider_priv_hex": priv.hex(),
        "name": "TestSvc",
        "kind": "api",
        "endpoint": "/api/v1/test",
        "scope": {},
        "approval_mode": "auto",
        "description": "desc",
    })
    assert r.status_code == 200, r.text
    service_id = r.json()["service_id"]

    r2 = client.get("/services")
    assert r2.status_code == 200
    assert any(s["service_id"] == service_id for s in r2.json())
```

- [ ] **Step 2: Run test to verify it fails (404 on /services)**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/test_services.py::test_api_get_services_empty tests/test_services.py::test_api_services_round_trip -v
```

Expected: FAIL with 404 (route not found)

- [ ] **Step 3: Add request models and endpoints to `api/main.py`**

After the existing `CanRequest` model, add:

```python
class ServiceOfferRequest(BaseModel):
    provider_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    provider_priv_hex: str
    name: str
    kind: str
    endpoint: str
    scope: Dict[str, Any] = Field(default_factory=dict)
    approval_mode: str = "auto"
    description: str = ""


class SubscribeRequest(BaseModel):
    subscriber_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    subscriber_priv_hex: str


class ApproveRejectRequest(BaseModel):
    actor_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    actor_priv_hex: str


class PullRequest(BaseModel):
    base_url: str = Field(..., description="Base URL of the remote node, e.g. https://node.example")
```

After the existing `/emancipate` endpoint, add the service endpoints:

```python
# ---------------------------------------------------------------------------
# Service endpoints — catalog + subscriptions
# ---------------------------------------------------------------------------


@app.get("/services")
async def list_services():
    """List all non-revoked service offers with approval_mode and provider."""
    from annuaire.verbs import _get_offers  # noqa: PLC0415
    j = get_journal()
    offers = _get_offers(j)
    return offers


@app.post("/service/offer", dependencies=[Depends(_require_jwt)])
async def service_offer(req: ServiceOfferRequest):
    """Publish a signed ServiceOffer to the catalog."""
    from annuaire.verbs import offer_service as _offer  # noqa: PLC0415
    priv = _priv_from_hex(req.provider_priv_hex)
    j = get_journal()
    try:
        offer = _offer(
            j, priv, req.provider_did,
            name=req.name,
            kind=req.kind,
            endpoint=req.endpoint,
            scope=req.scope,
            approval_mode=req.approval_mode,
            description=req.description,
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return offer.model_dump()


@app.post("/service/{service_id}/revoke", dependencies=[Depends(_require_jwt)])
async def service_revoke(service_id: str, req: ApproveRejectRequest):
    """Revoke a ServiceOffer (provider only)."""
    from annuaire.verbs import revoke_offer as _revoke  # noqa: PLC0415
    priv = _priv_from_hex(req.actor_priv_hex)
    j = get_journal()
    try:
        _revoke(j, priv, req.actor_did, service_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"status": "revoked", "service_id": service_id}


@app.post("/service/{service_id}/subscribe", dependencies=[Depends(_require_jwt)])
async def service_subscribe(service_id: str, req: SubscribeRequest):
    """Subscribe to a service offer; response includes derived subscription_state."""
    from annuaire.verbs import subscribe as _subscribe, subscription_state as _state  # noqa: PLC0415
    priv = _priv_from_hex(req.subscriber_priv_hex)
    j = get_journal()
    try:
        sub = _subscribe(j, priv, req.subscriber_did, service_id)
        state = _state(j, sub.subscription_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    result = sub.model_dump()
    result["subscription_state"] = state.value
    return result


@app.get("/subscriptions")
async def list_subscriptions(mine: Optional[str] = None, pending_for: Optional[str] = None):
    """List subscriptions with derived state.

    Optional filters:
      ?mine=<subscriber_did>  — only subscriptions for this subscriber.
      ?pending_for=<provider_did> — only PENDING subscriptions for this provider's services.
    """
    from annuaire.model import Op as _Op, SubscriptionState as _SS  # noqa: PLC0415
    from annuaire.verbs import subscription_state as _state, _get_offers  # noqa: PLC0415
    j = get_journal()

    # Collect all self-authored Subscription entries
    seen: Dict[str, dict] = {}
    for entry in j.iter_entries():
        if (entry.op == _Op.SERVICE_SUBSCRIBE
                and entry.payload_type == "Subscription"):
            payload = entry.payload
            sid = payload.get("subscription_id")
            subscriber = payload.get("subscriber")
            # Only self-authored
            if sid and subscriber and entry.author == subscriber:
                seen[sid] = payload

    result = []
    for sub_id, payload in seen.items():
        try:
            state = _state(j, sub_id)
        except ValueError:
            state = _SS.PENDING
        row = dict(payload)
        row["subscription_state"] = state.value
        result.append(row)

    # Filtering
    if mine:
        result = [r for r in result if r.get("subscriber") == mine]

    if pending_for:
        # Collect service_ids offered by pending_for
        offers = _get_offers(j)
        provider_sids = {o["service_id"] for o in offers if o.get("provider") == pending_for}
        result = [
            r for r in result
            if r.get("service_id") in provider_sids
            and r.get("subscription_state") == _SS.PENDING.value
        ]

    return result


@app.post("/subscription/{subscription_id}/approve", dependencies=[Depends(_require_jwt)])
async def subscription_approve(subscription_id: str, req: ApproveRejectRequest):
    """Approve a subscription (provider only)."""
    from annuaire.verbs import approve_subscription as _approve  # noqa: PLC0415
    priv = _priv_from_hex(req.actor_priv_hex)
    j = get_journal()
    try:
        _approve(j, priv, req.actor_did, subscription_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"status": "approved", "subscription_id": subscription_id}


@app.post("/subscription/{subscription_id}/reject", dependencies=[Depends(_require_jwt)])
async def subscription_reject(subscription_id: str, req: ApproveRejectRequest):
    """Reject a subscription (provider only)."""
    from annuaire.verbs import reject_subscription as _reject  # noqa: PLC0415
    priv = _priv_from_hex(req.actor_priv_hex)
    j = get_journal()
    try:
        _reject(j, priv, req.actor_did, subscription_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"status": "rejected", "subscription_id": subscription_id}


@app.post("/services/pull", dependencies=[Depends(_require_jwt)])
async def services_pull(req: PullRequest):
    """Pull and ingest service offers from a remote node's catalog.

    Fetches <base_url>/api/v1/annuaire/services, verifies each offer's sig,
    ingests valid ones. Returns {ingested: N, rejected: M, error: str|None}.
    """
    from annuaire.verbs import ingest_offer as _ingest  # noqa: PLC0415
    from annuaire.model import ServiceOffer as _SO  # noqa: PLC0415

    j = get_journal()
    ingested = 0
    rejected = 0
    error_msg = None

    target_url = req.base_url.rstrip("/") + "/api/v1/annuaire/services"

    try:
        # Try httpx first (preferred), fall back to urllib
        try:
            import httpx  # noqa: PLC0415
            response = httpx.get(target_url, timeout=10.0)
            response.raise_for_status()
            remote_offers = response.json()
        except ImportError:
            import urllib.request  # noqa: PLC0415
            import json as _json  # noqa: PLC0415
            import socket  # noqa: PLC0415
            with urllib.request.urlopen(target_url, timeout=10) as resp:  # nosec
                remote_offers = _json.loads(resp.read().decode())

        if not isinstance(remote_offers, list):
            error_msg = f"remote returned unexpected type: {type(remote_offers).__name__}"
        else:
            for raw in remote_offers:
                try:
                    offer = _SO(**raw)
                    # pubkey_hex must come from the offer — the remote node
                    # sends their Identity alongside, but here we trust the
                    # GET /services endpoint to return signed offers with the
                    # provider's pubkey embedded in the local Identity log.
                    # For federation: the caller must ensure the provider is
                    # already in the local journal (via auto_add), OR the
                    # remote API should include pubkey in the offer response.
                    # We read it from the local log (by provider did), or
                    # from a "pubkey_hex" field if present in the raw offer.
                    pubkey_hex = raw.get("pubkey_hex") or _get_inviter_pubkey(j, offer.provider)
                    if not pubkey_hex:
                        rejected += 1
                        continue
                    _ingest(j, offer, provider_pubkey_hex=pubkey_hex)
                    ingested += 1
                except Exception:
                    rejected += 1

    except Exception as exc:
        error_msg = str(exc)

    return {"ingested": ingested, "rejected": rejected, "error": error_msg}
```

Note: `_get_inviter_pubkey` must be imported at the top of the services_pull function. Add to existing imports at the bottom of `api/main.py`'s helper section:

```python
# In the /services/pull handler, import _get_inviter_pubkey locally:
# from annuaire.verbs import _get_inviter_pubkey  (inside the function)
```

Actually, replace the `_get_inviter_pubkey` call with a local import inside the endpoint:

```python
    from annuaire.verbs import _get_inviter_pubkey as _gpk  # noqa: PLC0415
    # ... then use _gpk(j, offer.provider) instead
```

- [ ] **Step 4: Run API smoke tests**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/test_services.py::test_api_get_services_empty tests/test_services.py::test_api_services_round_trip -v
```

Expected: 2 passed

- [ ] **Step 5: Run the full test suite**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/ -q
```

Expected: all pass

- [ ] **Step 6: Smoke-test the import**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -c "import sys; sys.path.insert(0,'.'); from api import main; print('ok', sorted({r.path for r in main.app.routes if hasattr(r,'path')})[:12])"
```

Expected: `ok ['/can', '/emancipate', '/health', '/invite', '/log', '/merkle-root', '/proposal', '/service/{service_id}/revoke', '/service/{service_id}/subscribe', '/service/offer', '/services', '/services/pull']` (order may vary but all paths present)

- [ ] **Step 7: Commit**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
git add api/main.py tests/test_services.py
git commit -m "feat(annuaire): FastAPI endpoints for service catalog + subscriptions + pull federation"
```

---

## Task 4: UI — Services panel in `www/annuaire/index.html`

**Files:**
- Modify: `www/annuaire/index.html`

**Interfaces:**
- Consumes: `GET /services`, `POST /service/{id}/subscribe`, `GET /subscriptions`
- No new backend changes

- [ ] **Step 1: Add Services panel to `www/annuaire/index.html`**

Replace the closing `</main>` and `<script>` block with this (keeps all existing panels and adds Services below):

The existing HTML ends at line 74. The new content replaces from `<h2>Trust log</h2>` through `</html>`, inserting the Services panel before the trust log. The new full replacement from `<h2>` to `</html>`:

```html
    <h2>Services</h2>
    <div id="svc-list"><p class="empty">Loading services…</p></div>

    <h2>My Subscriptions</h2>
    <div id="sub-list"><p class="empty">Loading subscriptions…</p></div>

    <h2>Trust log</h2>
    <table><thead><tr><th>#</th><th>op</th><th>type</th><th>author</th><th>when</th></tr></thead>
      <tbody id="log"><tr><td colspan="5" class="empty">Loading…</td></tr></tbody></table>
  </main>

  <script>
    const API='/api/v1/annuaire';
    async function j(p,opts){try{const r=await fetch(API+p,opts);if(!r.ok)throw new Error(r.status);return await r.json();}catch(e){return null;}}
    function esc(s){const d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML;}
    function shortdid(s){s=String(s||'');return s.length>22?s.slice(0,14)+'…'+s.slice(-5):s;}

    function badgeMode(m){
      const colors={auto:'var(--matrix-green,#00ff41)',pending:'var(--gold-hermetic,#c9a84c)'};
      return `<span class="op" style="border-color:${colors[m]||'var(--cyber-cyan)'};color:${colors[m]||'var(--cyber-cyan)'}">${esc(m)}</span>`;
    }
    function badgeState(s){
      const colors={approved:'var(--matrix-green,#00ff41)',pending:'var(--gold-hermetic,#c9a84c)',rejected:'var(--cinnabar,#e63946)',revoked:'var(--text-muted,#6b6b7a)'};
      return `<span class="op" style="border-color:${colors[s]||'var(--cyber-cyan)'};color:${colors[s]||'var(--cyber-cyan)'}">${esc(s)}</span>`;
    }

    async function subscribe(serviceId){
      const sub_did=prompt('Your DID (did:plc:...)');
      const sub_priv=prompt('Your private key (hex, 64 chars)');
      if(!sub_did||!sub_priv)return;
      const r=await j('/service/'+serviceId+'/subscribe',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({subscriber_did:sub_did,subscriber_priv_hex:sub_priv})
      });
      if(!r){alert('Subscribe failed');return;}
      alert('Subscription state: '+(r.subscription_state||'unknown'));
      loadServices();loadSubs();
    }

    async function loadServices(){
      const services=await j('/services');
      const el=document.getElementById('svc-list');
      if(!services||!services.length){el.innerHTML='<p class="empty">No services advertised yet.</p>';return;}
      el.innerHTML='<table><thead><tr><th>Name</th><th>Kind</th><th>Provider</th><th>Approval</th><th>Action</th></tr></thead><tbody>'+
        services.map(s=>`<tr>
          <td>${esc(s.name)}</td>
          <td>${esc(s.kind)}</td>
          <td class="mono" title="${esc(s.provider)}">${esc(shortdid(s.provider))}</td>
          <td>${badgeMode(s.approval_mode)}</td>
          <td><button class="btn-sm" onclick="subscribe('${esc(s.service_id)}')">Subscribe</button></td>
        </tr>`).join('')+'</tbody></table>';
    }

    async function loadSubs(){
      const subs=await j('/subscriptions');
      const el=document.getElementById('sub-list');
      if(!subs||!subs.length){el.innerHTML='<p class="empty">No subscriptions yet.</p>';return;}
      el.innerHTML='<table><thead><tr><th>Service</th><th>Subscriber</th><th>State</th></tr></thead><tbody>'+
        subs.map(s=>`<tr>
          <td class="mono">${esc(shortdid(s.service_id))}</td>
          <td class="mono" title="${esc(s.subscriber)}">${esc(shortdid(s.subscriber))}</td>
          <td>${badgeState(s.subscription_state)}</td>
        </tr>`).join('')+'</tbody></table>';
    }

    async function load(){
      const st=await j('/status');
      if(st){
        const ok=st.chain_ok!==false;
        const cb=document.getElementById('chain'); cb.textContent=ok?'VERIFIED':('BROKEN @'+st.chain_broken_at);
        cb.className='v '+(ok?'ok':'bad');
        document.getElementById('chain-badge').textContent='chain '+(ok?'✓':'✗');
        document.getElementById('height').textContent=(st.tip_height==null||st.tip_height<0)?'0 (empty)':st.tip_height;
        document.getElementById('merkle').textContent=st.merkle_root||'—';
      }
      await loadServices();
      await loadSubs();
      const log=await j('/log');
      const tb=document.getElementById('log');
      const rows=Array.isArray(log)?log:(log&&Array.isArray(log.entries)?log.entries:[]);
      if(!rows.length){tb.innerHTML='<tr><td colspan="5" class="empty">No log entries yet — the trust graph is empty.</td></tr>';return;}
      tb.innerHTML=rows.slice(-50).reverse().map(e=>`<tr>
        <td>${esc(e.height)}</td><td><span class="op">${esc(e.op||(e.payload&&e.payload_type)||'?')}</span></td>
        <td>${esc(e.payload_type||'')}</td><td class="mono" title="${esc(e.author)}">${esc(shortdid(e.author))}</td>
        <td class="mono">${esc((e.ts||e.timestamp||e.created_at||'').toString().replace('T',' ').slice(0,19))}</td></tr>`).join('');
    }
    document.addEventListener('DOMContentLoaded',load);
    setInterval(load,15000);
  </script>
  <script src="/shared/crt-engine.js"></script>
</body>
</html>
```

Also add CSS for the Subscribe button in `<style>`:

```css
    .btn-sm{background:var(--panel,#13131c);border:1px solid var(--cyber-cyan,#00d4ff);color:var(--cyber-cyan,#00d4ff);border-radius:6px;padding:3px 10px;cursor:pointer;font-size:11px}
    .btn-sm:hover{background:var(--cyber-cyan,#00d4ff);color:var(--cosmos-black,#0a0a0f)}
```

- [ ] **Step 2: Verify HTML is well-formed and tests still pass**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/ -q
python3 -c "
import html.parser, pathlib
class P(html.parser.HTMLParser):
    def __init__(self): super().__init__(); self.errors=[]
p=P()
p.feed(pathlib.Path('www/annuaire/index.html').read_text())
print('HTML parsed OK')
"
```

Expected: all tests green, `HTML parsed OK`

- [ ] **Step 3: Commit**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
git add www/annuaire/index.html
git commit -m "feat(annuaire): Services + Subscriptions panel in dashboard UI"
```

---

## Task 5: Packaging — bump changelog to 0.1.3, build .deb

**Files:**
- Modify: `debian/changelog`

- [ ] **Step 1: Add changelog entry**

Prepend to `debian/changelog`:

```
secubox-annuaire (0.1.3-1~bookworm1) bookworm; urgency=medium

  * feat: service offers + subscription (auto/pending approval) + pull federation
  * New enums: ApprovalMode (auto/pending), SubscriptionState (pending/approved/rejected/revoked)
  * New log ops: SERVICE_OFFER, SERVICE_REVOKE_OFFER, SERVICE_SUBSCRIBE, SERVICE_APPROVE,
    SERVICE_REJECT, SERVICE_REVOKE_SUB
  * New models: ServiceOffer, Subscription (self-certifying, BLAKE2b-chained)
  * New verbs: offer_service, revoke_offer, subscribe, approve_subscription,
    reject_subscription, revoke_subscription, subscription_state, ingest_offer
  * New API endpoints: GET /services, POST /service/offer, POST /service/{id}/revoke,
    POST /service/{id}/subscribe, GET /subscriptions, POST /subscription/{id}/approve,
    POST /subscription/{id}/reject, POST /services/pull (federation pull)
  * UI: Services + Subscriptions panel in dashboard
  * Tests: tests/test_services.py covers all authorization paths

 -- Gerald KERMA <devel@cybermind.fr>  Tue, 30 Jun 2026 12:00:00 +0200
```

- [ ] **Step 2: Final full test run**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -m pytest tests/ -q
```

Expected: all green, no regressions

- [ ] **Step 3: Run the smoke import check**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
python3 -c "import sys; sys.path.insert(0,'.'); from api import main; print('ok', sorted({r.path for r in main.app.routes if hasattr(r,'path')})[:8])"
```

Expected: `ok` + list of paths including `/services` and `/service/{service_id}/subscribe`

- [ ] **Step 4: Build the .deb**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
dpkg-buildpackage -us -uc -b 2>&1 | tail -5
```

Expected: `dpkg-deb: building package 'secubox-annuaire' in '../secubox-annuaire_0.1.3-1~bookworm1_all.deb'.`

- [ ] **Step 5: Final commit**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-annuaire
git add debian/changelog
git commit -m "feat(annuaire): service offers + subscription (auto/pending approval) + pull federation"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| `ApprovalMode` enum (auto/pending) | Task 1 |
| `SubscriptionState` enum (pending/approved/rejected/revoked) | Task 1 |
| 6 new `Op` members | Task 1 |
| `ServiceOffer` model (all fields) | Task 1 |
| `Subscription` model (all fields) | Task 1 |
| `offer_service` verb (MEMBER check, self-authored) | Task 2 |
| `revoke_offer` (provider-only) | Task 2 |
| `subscribe` (MEMBER check, offer must exist) | Task 2 |
| `approve_subscription` (provider-only auth) | Task 2 |
| `reject_subscription` (provider-only auth) | Task 2 |
| `_get_offers` helper | Task 2 |
| `_get_offer` helper | Task 2 |
| `subscription_state` derived (auto→approved, defense in depth) | Task 2 |
| `ingest_offer` (verify sig, reject forged, preserve author) | Task 2 |
| `GET /services` | Task 3 |
| `POST /service/offer` (auth) | Task 3 |
| `POST /service/{id}/revoke` (auth) | Task 3 |
| `POST /service/{id}/subscribe` (auth, returns derived state) | Task 3 |
| `GET /subscriptions` (mine + pending_for filters) | Task 3 |
| `POST /subscription/{id}/approve` (auth) | Task 3 |
| `POST /subscription/{id}/reject` (auth) | Task 3 |
| `POST /services/pull` (fetch remote, ingest, robust to offline) | Task 3 |
| UI Services panel + Subscribe button | Task 4 |
| UI My Subscriptions list with state | Task 4 |
| SPDX header on new test file | Task 2 (in test file header) |
| 104 original tests preserved | Tasks 1-5 |
| New tests: all required scenarios | Task 2 |
| Changelog bump 0.1.3 | Task 5 |
| Build .deb | Task 5 |

**Placeholder scan:** None found. All steps have exact code.

**Type consistency check:**
- `_get_offers` returns `List[Dict]` (raw payload dicts) — used consistently in API endpoints and tests
- `ServiceOffer.sig` is `Optional[str]` — consistent with `Invitation.sig` pattern
- `subscription_state()` returns `SubscriptionState` enum — API converts to `.value` for JSON
- `ingest_offer(journal, offer, provider_pubkey_hex)` — `provider_pubkey_hex` is explicit param, not looked up from log (design decision: avoids trusting local log for remote pubkeys)
- `revoke_subscription` is defined in verbs.py and imported in test — ✓

**Design note on `ingest_offer` pubkey resolution:** The `provider_pubkey_hex` is a required explicit parameter. When the `/services/pull` endpoint calls `ingest_offer`, it first tries `raw.get("pubkey_hex")` (the remote node may annotate each offer with their pubkey), then falls back to `_get_inviter_pubkey(j, offer.provider)` (if the provider is already in the local log via a prior `auto_add`). This is documented in the pull endpoint. Callers who pull from an unknown node should first call `POST /auto-add` with the remote node's identity.
