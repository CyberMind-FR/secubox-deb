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
        author = _author(entry)
        if not author:
            continue
        if has_release_grant(entries, author, self_did):
            ring = p["ring"]
    return ring
