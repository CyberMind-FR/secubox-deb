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


def test_box_ring_uses_verified_author_not_payload_issued_by():
    # CENTER holds a release grant from the box; OTHER does not.
    # A RING_ASSIGN signed by OTHER but claiming issued_by=CENTER must be ignored.
    forged = {"op": Op.RING_ASSIGN.value,
              "payload": {"box_did": BOX, "ring": "internal", "issued_by": CENTER},
              "author": OTHER}
    entries = [_grant(CENTER), forged]
    assert rl.box_ring(entries, BOX, self_did=BOX) == "published"


# ---------------------------------------------------------------------------
# current_ring sovereignty filter (self_did): a RELEASE_PROMOTE/DEMOTE counts
# only when its VERIFIED author holds a release grant from the honoring box.
# Without it, an ungranted center's federated promote would drive sync-repo's
# reprepro copy fleet-wide. self_did=None keeps the unfiltered resolver.
# ---------------------------------------------------------------------------

def test_current_ring_ignores_promote_by_ungranted_author():
    # OTHER promotes but holds no release grant from BOX -> ignored, stays draft.
    entries = [e(Op.RELEASE_PUBLISH, evo_id="e1", issued_by=CENTER),
               e(Op.RELEASE_PROMOTE, evo_id="e1", ring="internal", issued_by=OTHER)]
    assert rl.current_ring(entries, "e1", self_did=BOX) == "draft"
    # unfiltered (compat) view still honors it
    assert rl.current_ring(entries, "e1") == "internal"


def test_current_ring_counts_promote_by_granted_author():
    # CENTER holds a release grant from BOX -> its promote counts.
    entries = [_grant(CENTER),
               e(Op.RELEASE_PUBLISH, evo_id="e1", issued_by=CENTER),
               e(Op.RELEASE_PROMOTE, evo_id="e1", ring="internal", issued_by=CENTER)]
    assert rl.current_ring(entries, "e1", self_did=BOX) == "internal"


def test_current_ring_ignores_authorless_promote_under_self_did():
    # An entry with no verified author must never count under sovereign view.
    entries = [_grant(CENTER),
               e(Op.RELEASE_PUBLISH, evo_id="e1", issued_by=CENTER),
               {"op": Op.RELEASE_PROMOTE.value,
                "payload": {"evo_id": "e1", "ring": "internal"}}]  # no author
    assert rl.current_ring(entries, "e1", self_did=BOX) == "draft"
