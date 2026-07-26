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


def published_evo_ids(entries: List[Mapping[str, Any]]) -> List[str]:
    """The evo_ids that carry a RELEASE_PUBLISH, in first-seen order (deduped).

    Public accessor so read paths (ctl cmd_list/cmd_sync_repo, api /evolutions)
    stop reaching into grants._op/_payload privately to collect published ids.
    """
    seen: dict = {}
    for p in _by(entries, Op.RELEASE_PUBLISH):
        evo = p.get("evo_id")
        if evo is not None:
            seen.setdefault(evo, None)
    return list(seen.keys())


def current_ring(entries: List[Mapping[str, Any]], evo_id: str,
                 self_did: Optional[str] = None) -> Optional[str]:
    """Resolve the current ring of *evo_id*, or None if it was never published.

    SOVEREIGNTY (fail-closed): when *self_did* is given, a RELEASE_PROMOTE/DEMOTE
    counts only when its VERIFIED author holds an active capability="release"
    grant issued BY THIS BOX (self_did). Ring ops federate (dir_sync), so an
    ungranted peer could otherwise publish fleet-wide by authoring a promote
    that sync-repo's reprepro copy would then honor. An entry with no author, or
    an author lacking a release grant from self_did, is ignored. When
    *self_did* is None (default) NO author filter is applied — retained only for
    the pure-resolver unit tests; every sovereign call site passes self_did.
    """
    if evo_id not in published_evo_ids(entries):
        return None
    ring = "draft"
    for entry in entries:
        o = _op(entry)
        if o in (Op.RELEASE_PROMOTE.value, Op.RELEASE_DEMOTE.value):
            p = _payload(entry)
            if p.get("evo_id") == evo_id and p.get("ring") in RINGS:
                if self_did is not None:
                    author = _author(entry)
                    if not author or not has_release_grant(entries, author, self_did):
                        continue
                ring = p["ring"]
    return ring


def evolutions_in_ring(entries: List[Mapping[str, Any]], ring: str,
                       self_did: Optional[str] = None) -> List[str]:
    ids = published_evo_ids(entries)
    return [i for i in ids if current_ring(entries, i, self_did) == ring]


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
        author = _author(entry)
        if not author:
            continue
        if has_release_grant(entries, author, self_did):
            ring = p["ring"]
    return ring
