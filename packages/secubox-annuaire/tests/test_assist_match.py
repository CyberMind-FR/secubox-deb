# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from annuaire.model import Op, now_rfc3339
from annuaire import assist_match as m

A = "did:plc:" + "1" * 32
B = "did:plc:" + "2" * 32
C = "did:plc:" + "3" * 32  # third party — never a legitimate offer/request author below


def e(op, author=None, **p):
    """Build a journal-entry dict. `author` is the AUTHENTICATED signer (the
    field the real Journal sets from the signing key) — defaults to the
    payload's `issued_by` for happy-path fixtures. Adversarial tests override
    `author` explicitly to simulate a signer whose payload lies about
    `issued_by` (spoofing) or whose op targets someone else's object
    (foreign revoke / forged accept).
    """
    if author is None:
        author = p.get("issued_by")
    return {"op": op.value, "author": author, "payload": p}


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


def test_malformed_ttl_fails_closed():
    entries = [_offer("o1", ["lora"], ttl="not-a-number"), _req("r1", ["lora"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
    assert m.active_offers(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_malformed_created_at_fails_closed():
    entries = [_offer("o1", ["lora"], at="garbage"), _req("r1", ["lora"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
    assert m.active_offers(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_matches_with_now_rfc3339_format():
    # created_at stamped with the real model default_factory shape
    # (datetime.isoformat(): microseconds + "+00:00" offset), NOT the
    # "Z"-suffixed, second-precision form the strict parser used to require.
    stamp = now_rfc3339()
    entries = [_offer("o1", ["lora"], at=stamp), _req("r1", ["lora"], at=stamp)]
    ms = m.matches(entries, now_ts=now_rfc3339())
    assert len(ms) == 1 and ms[0][2] == m.match_id("o1", "r1")


def test_match_ready_needs_both_sides():
    mid = m.match_id("o1", "r1")
    base = [_offer("o1", ["lora"]), _req("r1", ["lora"])]
    only_offer = base + [e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1",
                           req_id="r1", side="offer", issued_by=A)]
    assert not m.match_ready(only_offer, mid, now_ts="2026-07-25T10:30:00Z")
    both = only_offer + [e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1",
                           req_id="r1", side="request", issued_by=B)]
    assert m.match_ready(both, mid, now_ts="2026-07-25T10:30:00Z")


# ---------------------------------------------------------------------------
# Adversarial — author-binding (any signed mesh member is a potential attacker)
# ---------------------------------------------------------------------------

def test_foreign_revoke_ignored():
    """Node B revokes node A's offer. Since B is not the offer's author, the
    revoke must NOT withdraw it — offer o1 stays active and still matches."""
    entries = [_offer("o1", ["lora"], by=A), _req("r1", ["lora"], by=B),
               e(Op.ASSIST_OFFER_REVOKE, offer_id="o1", issued_by=B)]  # author=B (default)
    ms = m.matches(entries, now_ts="2026-07-25T10:30:00Z")
    assert len(ms) == 1 and ms[0][2] == m.match_id("o1", "r1")
    assert len(m.active_offers(entries, now_ts="2026-07-25T10:30:00Z")) == 1


def test_forged_mutual_accept_rejected():
    """A single third party C posts BOTH side="offer" and side="request"
    accepts for a match between A's offer and B's request. C authored
    neither the offer nor the request, so match_ready must stay False."""
    mid = m.match_id("o1", "r1")
    entries = [_offer("o1", ["lora"], by=A), _req("r1", ["lora"], by=B),
               e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1", req_id="r1",
                 side="offer", issued_by=C, author=C),
               e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1", req_id="r1",
                 side="request", issued_by=C, author=C)]
    assert not m.match_ready(entries, mid, now_ts="2026-07-25T10:30:00Z")


def test_spoofed_issued_by_dropped():
    """An ASSIST_REQUEST_OPEN authored by A but claiming issued_by=B (victim)
    must be dropped entirely — it must not appear in active_open_requests
    nor produce a match."""
    entries = [e(Op.ASSIST_REQUEST_OPEN, req_id="r1", tags=["lora"], scope=None,
                 ttl_s=3600, reason="x", issued_by=B, created_at="2026-07-25T10:00:00Z",
                 author=A),  # spoofed: signer is A, payload claims issued_by=B
               _offer("o1", ["lora"], by=A)]
    assert m.active_open_requests(entries, now_ts="2026-07-25T10:30:00Z") == []
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_matches_skips_offer_missing_id():
    """A validly-signed, non-expired offer with no offer_id must not crash
    matches() with a KeyError — it must simply be excluded (fail-closed)."""
    entries = [e(Op.ASSIST_OFFER, tags=["lora"], scope=None, ttl_s=3600,
                 issued_by=A, created_at="2026-07-25T10:00:00Z"),  # no offer_id
               _req("r1", ["lora"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
