# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: resolver
The can() resolver — the centralized access adjudicator for the trust substrate.

can() implements the §1.1 *audited reconciliation* test:
  (a) identity self-certification valid (name IS the hash of the key)
  (b) log non-equivocation (chain verifies — tamper detectable)
  (c) non-revoked membership (via NIZK interface; v0 = log state)
  (d) a contextual, dated, non-revoked, in-scope Attestation exists for the action

All four legs must hold.  A missing leg yields allowed=False with reconciled=False
("unreconciled", NOT trusted) — never silently upgraded to trust.

Design notes:
  - Centralizing the *resolver* gives one auditable adjudication path (CSPN).
    It does NOT centralize *trust* — identities, attestations, NIZK membership,
    and witnesses are produced independently across federated islands.
  - Attestation transitivity is BOUNDED (max_depth=2) and NEVER silent (§6.4).
  - OBSERVED status alone never grants MEMBER-gated actions (§3.1 hard rule).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set

from .crypto import verify_nizk
from .model import Attestation, Identity, LogEntry, MemberState, Op


# ---------------------------------------------------------------------------
# Right-sets per membership state (spec §4.4)
# OBSERVED is deliberately near-powerless — no standing, no MEMBER-gated ops.
# ---------------------------------------------------------------------------

RIGHTS: dict[MemberState, Set[str]] = {
    MemberState.OBSERVED: {"read.public"},
    MemberState.MEMBER: {
        "read.public",
        "attest",
        "vote",
        "invite",
        "report.threat",
        "name.bind",
        "service.publish",
        "config.publish",   # gondwana P1 (#768): publish signed config/node records
    },
    MemberState.REVOKED: set(),
}

# Actions that require a contextual Attestation in addition to membership
_ATTESTATION_GATED: Set[str] = {
    "attest",
    "vote",
    "invite",
    "name.bind",
    "service.publish",
    "report.threat",
}


# ---------------------------------------------------------------------------
# Decision — the structured return value
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    """Structured result of a can() query.

    allowed: True only when ALL four legs of the audited reconciliation hold.
    reasons: list of human-readable strings — the audit trail for the decision.
             Always at least one element.
    """
    allowed: bool
    reasons: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Log-state helpers
# ---------------------------------------------------------------------------

def _latest_identity_for(
    journal,  # Journal instance
    subject_did: str,
) -> Optional[Identity]:
    """Return the most recently logged SELF-AUTHORED Identity object for *subject_did*.

    Fix 1: an Identity entry authored by someone other than its subject is
    invalid for state purposes and must be ignored.
    """
    best: Optional[LogEntry] = None
    for entry in journal.iter_entries():
        if entry.payload_type == "Identity" and entry.payload.get("did") == subject_did:
            # Fix 1: only self-authored entries contribute to identity state
            if entry.author != subject_did:
                continue
            if best is None or entry.height > best.height:
                best = entry
    if best is None:
        return None
    try:
        return Identity(**best.payload)
    except Exception:
        return None


def _authorized_revoked_dids_resolver(journal) -> Set[str]:
    """Return dids revoked by an authorized RevocationNotice (for use in resolver).

    Mirrors the logic in verbs._authorized_revoked_dids() — duplicated here to
    avoid an import cycle (resolver must not import verbs if verbs imports resolver).

    A RevocationNotice (op REVOKE) is authorized iff its revoker is:
      - the target itself (self-revocation), OR
      - the invited_by (grafter) of target's latest SELF-AUTHORED Identity.

    Also honors self-authored Identity{state=REVOKED} entries (Fix 3).
    """
    from .model import MemberState as _MS  # local to avoid shadowing outer import

    # Build {did: (latest_self_authored_invited_by, latest_self_authored_state)}
    latest_invited_by: dict = {}
    latest_self_state: dict = {}
    for entry in journal.iter_entries():
        if entry.payload_type == "Identity":
            did = entry.payload.get("did")
            if did and entry.author == did:
                latest_invited_by[did] = entry.payload.get("invited_by")
                latest_self_state[did] = entry.payload.get("state", "")

    authorized_revoked: Set[str] = set()

    # 1. Self-authored Identity{state=REVOKED} → self-revocation
    for did, state in latest_self_state.items():
        if state == _MS.REVOKED.value:
            authorized_revoked.add(did)

    # 2. Authorized RevocationNotice
    for entry in journal.iter_entries():
        if entry.op == Op.REVOKE and entry.payload_type == "RevocationNotice":
            target = entry.payload.get("target")
            revoker = entry.payload.get("revoker")
            if not target or not revoker:
                continue
            if revoker == target:
                authorized_revoked.add(target)
                continue
            grafter = latest_invited_by.get(target)
            if grafter and revoker == grafter:
                authorized_revoked.add(target)

    return authorized_revoked


def _build_log_state(journal) -> dict:
    """Derive (members, revoked) sets from the journal for v0 NIZK.

    Fix 1: only SELF-AUTHORED Identity entries contribute to membership state.
    Fix 3: revoked set derived from authorized RevocationNotice entries in addition
    to self-authored Identity{state=REVOKED} entries.
    """
    members: Set[str] = set()
    for entry in journal.iter_entries():
        if entry.payload_type == "Identity":
            did = entry.payload.get("did")
            state = entry.payload.get("state")
            # Fix 1: only self-authored entries
            if did and entry.author == did:
                if state == MemberState.MEMBER.value:
                    members.add(did)
                elif state in (MemberState.REVOKED.value, MemberState.OBSERVED.value):
                    members.discard(did)

    # Fix 3: derive revoked from authorized notices
    revoked = _authorized_revoked_dids_resolver(journal)
    return {"members": members - revoked, "revoked": revoked}


def _has_attestation(
    journal,
    subject_did: str,
    context: str,
    domain: str,
    max_depth: int = 2,
) -> bool:
    """Return True if a valid, non-revoked, in-scope Attestation exists.

    Depth is BOUNDED (max_depth ≤ 2) — no silent unbounded WoT transitivity
    (spec §6.4 anti-goal).  v0: only direct (depth=1) attestations checked.
    The depth parameter is accepted for forward-compatibility but bounded.
    """
    max_depth = min(max_depth, 2)  # hard cap; never unbounded
    for entry in journal.iter_entries():
        if entry.payload_type == "Attestation":
            a_payload = entry.payload
            if (
                a_payload.get("subject") == subject_did
                and a_payload.get("context") == context
                and a_payload.get("domain") == domain
                and not a_payload.get("revoked", False)
            ):
                return True
    return False


# ---------------------------------------------------------------------------
# can() — the centralized adjudicator
# ---------------------------------------------------------------------------

def can(
    journal,
    subject_did: str,
    action: str,
    target: str,
    *,
    domain: str,
    nizk_verifier: Optional[Callable] = None,
    nizk_proof: Optional[bytes] = None,
) -> Decision:
    """Decide whether *subject_did* may perform *action* on *target* in *domain*.

    Implements the §1.1 four-leg audited reconciliation:
      (a) identity self-certification
      (b) log chain integrity (tamper detection)
      (c) non-revoked membership (NIZK; v0 = log state)
      (d) contextual, non-revoked, in-scope Attestation

    Returns:
        Decision(allowed=True, reasons=[...]) if all four legs hold.
        Decision(allowed=False, reasons=[...]) with at least one reason otherwise.
    """
    # ------------------------------------------------------------------
    # (b) Log integrity — non-equivocation.  MUST be checked BEFORE
    #     reading anything from the log, so a tampered log never grants access.
    # ------------------------------------------------------------------
    chain_ok, broken_at = journal.verify_chain()
    if not chain_ok:
        return Decision(
            allowed=False,
            reasons=[
                f"log chain broken at height {broken_at} — "
                "possible tamper/equivocation detected"
            ],
        )

    # ------------------------------------------------------------------
    # (a) Identity self-certification
    # ------------------------------------------------------------------
    ident = _latest_identity_for(journal, subject_did)
    if ident is None:
        return Decision(
            allowed=False,
            reasons=["unknown identity — no Identity entry in log"],
        )

    # self_cert_digest must equal the did suffix (the name IS the key)
    did_suffix = subject_did.removeprefix("did:plc:")
    if ident.self_cert_digest != did_suffix:
        return Decision(
            allowed=False,
            reasons=["identity not self-certifying — self_cert_digest ≠ did suffix"],
        )

    # ------------------------------------------------------------------
    # State gate — REVOKED may do nothing; OBSERVED may only read.public
    # Fix 3: also deny dids in the authorized-revoked set (covers the path
    # where revocation is recorded via RevocationNotice rather than a
    # REVOKED Identity entry authored by the revoker).
    # ------------------------------------------------------------------
    if ident.state == MemberState.REVOKED:
        return Decision(
            allowed=False,
            reasons=["revoked — this identity has been withdrawn from the trust graph"],
        )

    # Fix 3: check authorized RevocationNotice path
    authorized_revoked = _authorized_revoked_dids_resolver(journal)
    if subject_did in authorized_revoked:
        return Decision(
            allowed=False,
            reasons=["revoked — this identity has been withdrawn from the trust graph "
                     "(authorized revocation notice)"],
        )

    state_rights = RIGHTS.get(ident.state, set())
    if action not in state_rights:
        return Decision(
            allowed=False,
            reasons=[
                f"{ident.state.value} state lacks right '{action}' "
                f"(available: {sorted(state_rights)})"
            ],
        )

    # ------------------------------------------------------------------
    # (c) Non-revoked membership — NIZK (v0: log-state check)
    # ------------------------------------------------------------------
    if action != "read.public":
        log_state = _build_log_state(journal)
        _nizk_verify = nizk_verifier if nizk_verifier is not None else verify_nizk
        if not _nizk_verify(
            proof=nizk_proof,
            domain=domain,
            subject_did=subject_did,
            log_state=log_state,
        ):
            return Decision(
                allowed=False,
                reasons=[
                    "membership NIZK absent or invalid — "
                    "non-revoked membership not proven for this domain"
                ],
            )

    # ------------------------------------------------------------------
    # (d) Contextual Attestation — NOT blind transitivity (spec §6.4)
    # ------------------------------------------------------------------
    if action in _ATTESTATION_GATED:
        if not _has_attestation(
            journal,
            subject_did=subject_did,
            context=target,
            domain=domain,
            max_depth=2,  # bounded; never unbounded WoT
        ):
            return Decision(
                allowed=False,
                reasons=[
                    f"no in-scope attestation for context='{target}' domain='{domain}' — "
                    "a direct, non-revoked, contextual Attestation is required"
                ],
            )

    # All four legs passed
    return Decision(
        allowed=True,
        reasons=["reconciled — all four legs of audited reconciliation hold"],
    )
