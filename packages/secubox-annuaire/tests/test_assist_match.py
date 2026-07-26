# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from annuaire.model import Op, now_rfc3339
from annuaire import assist_match as m

A = "did:plc:" + "1" * 32
B = "did:plc:" + "2" * 32
C = "did:plc:" + "3" * 32  # third party — never a legitimate offer/request author below


def wid(did, suffix):
    """Build a well-formed, author-self-certifying id: <author_prefix>-<suffix>."""
    return m.author_prefix(did) + "-" + suffix


def e(op, author=None, **p):
    """Build a journal-entry dict. `author` is the AUTHENTICATED signer (the
    field the real Journal sets from the signing key) — defaults to the
    payload's `issued_by`. Adversarial tests override `author` explicitly to
    simulate a signer whose payload lies about `issued_by` (spoofing) or
    whose op targets someone else's object (foreign revoke / forged accept).
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
    oid, rid = wid(A, "o1"), wid(B, "r1")
    entries = [_offer(oid, ["lora", "meshtastic"]), _req(rid, ["lora"])]
    ms = m.matches(entries, now_ts="2026-07-25T10:30:00Z")
    assert len(ms) == 1 and ms[0][2] == m.match_id(oid, rid)


def test_no_tag_overlap_no_match():
    entries = [_offer(wid(A, "o1"), ["lora"]), _req(wid(B, "r1"), ["dns"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_scope_must_agree_when_both_set():
    entries = [_offer(wid(A, "o1"), ["lora"], scope="dns"),
               _req(wid(B, "r1"), ["lora"], scope="firewall")]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
    entries2 = [_offer(wid(A, "o2"), ["lora"], scope="dns"),
                _req(wid(B, "r2"), ["lora"], scope="dns")]
    assert len(m.matches(entries2, now_ts="2026-07-25T10:30:00Z")) == 1


def test_expiry_fail_closed():
    entries = [_offer(wid(A, "o1"), ["lora"], ttl=60), _req(wid(B, "r1"), ["lora"], ttl=60)]
    # created 10:00:00, ttl 60s → expires 10:01:00; at 10:30 both stale
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_revoke_drops_offer():
    oid = wid(A, "o1")
    entries = [_offer(oid, ["lora"]), _req(wid(B, "r1"), ["lora"]),
               e(Op.ASSIST_OFFER_REVOKE, offer_id=oid, issued_by=A)]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_malformed_ttl_fails_closed():
    entries = [_offer(wid(A, "o1"), ["lora"], ttl="not-a-number"), _req(wid(B, "r1"), ["lora"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
    assert m.active_offers(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_malformed_created_at_fails_closed():
    entries = [_offer(wid(A, "o1"), ["lora"], at="garbage"), _req(wid(B, "r1"), ["lora"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
    assert m.active_offers(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_matches_with_now_rfc3339_format():
    # created_at stamped with the real model default_factory shape
    # (datetime.isoformat(): microseconds + "+00:00" offset), NOT the
    # "Z"-suffixed, second-precision form the strict parser used to require.
    stamp = now_rfc3339()
    oid, rid = wid(A, "o1"), wid(B, "r1")
    entries = [_offer(oid, ["lora"], at=stamp), _req(rid, ["lora"], at=stamp)]
    ms = m.matches(entries, now_ts=now_rfc3339())
    assert len(ms) == 1 and ms[0][2] == m.match_id(oid, rid)


def test_match_ready_needs_both_sides():
    oid, rid = wid(A, "o1"), wid(B, "r1")
    mid = m.match_id(oid, rid)
    base = [_offer(oid, ["lora"]), _req(rid, ["lora"])]
    only_offer = base + [e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id=oid,
                           req_id=rid, side="offer", issued_by=A)]
    assert not m.match_ready(only_offer, mid, now_ts="2026-07-25T10:30:00Z")
    both = only_offer + [e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id=oid,
                           req_id=rid, side="request", issued_by=B)]
    assert m.match_ready(both, mid, now_ts="2026-07-25T10:30:00Z")


# ---------------------------------------------------------------------------
# Adversarial — author-binding (any signed mesh member is a potential attacker)
# ---------------------------------------------------------------------------

def test_foreign_revoke_ignored():
    """Node B revokes node A's offer. Since B is not the offer's author, the
    revoke must NOT withdraw it — offer o1 stays active and still matches."""
    oid, rid = wid(A, "o1"), wid(B, "r1")
    entries = [_offer(oid, ["lora"], by=A), _req(rid, ["lora"], by=B),
               e(Op.ASSIST_OFFER_REVOKE, offer_id=oid, issued_by=B)]  # author=B (default)
    ms = m.matches(entries, now_ts="2026-07-25T10:30:00Z")
    assert len(ms) == 1 and ms[0][2] == m.match_id(oid, rid)
    assert len(m.active_offers(entries, now_ts="2026-07-25T10:30:00Z")) == 1


def test_forged_mutual_accept_rejected():
    """A single third party C posts BOTH side="offer" and side="request"
    accepts for a match between A's offer and B's request. C authored
    neither the offer nor the request, so match_ready must stay False."""
    oid, rid = wid(A, "o1"), wid(B, "r1")
    mid = m.match_id(oid, rid)
    entries = [_offer(oid, ["lora"], by=A), _req(rid, ["lora"], by=B),
               e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id=oid, req_id=rid,
                 side="offer", issued_by=C, author=C),
               e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id=oid, req_id=rid,
                 side="request", issued_by=C, author=C)]
    assert not m.match_ready(entries, mid, now_ts="2026-07-25T10:30:00Z")


def test_match_ready_rejects_third_party_owned_ids():
    """Attacker C owns his OWN active offer o2 and request r2 (so the
    author-binding checks on o2/r2 pass), then posts BOTH
    ASSIST_MATCH_ACCEPT sides for the REAL mid = match_id(o1, r1) — A's
    offer and B's request — but with offer_id="o2"/req_id="r2" (his own
    ids) instead of o1/r1. match_ready must not credit these accepts
    toward mid: the accept's (offer_id, req_id) pair must itself hash to
    mid before it can count, and o2/r2 do not. C never accepted on A/B's
    behalf, so this must NOT forge mutual consent for o1/r1."""
    oid, rid = wid(A, "o1"), wid(B, "r1")
    oid2, rid2 = wid(C, "o2"), wid(C, "r2")
    mid = m.match_id(oid, rid)
    entries = [
        _offer(oid, ["lora"], by=A),
        _req(rid, ["lora"], by=B),
        _offer(oid2, ["lora"], by=C),
        _req(rid2, ["lora"], by=C),
        e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id=oid2, req_id=rid2,
          side="offer", issued_by=C, author=C),
        e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id=oid2, req_id=rid2,
          side="request", issued_by=C, author=C),
    ]
    assert not m.match_ready(entries, mid, now_ts="2026-07-25T10:30:00Z")


def test_spoofed_issued_by_dropped():
    """An ASSIST_REQUEST_OPEN authored by A but claiming issued_by=B (victim)
    must be dropped entirely — it must not appear in active_open_requests
    nor produce a match."""
    entries = [e(Op.ASSIST_REQUEST_OPEN, req_id=wid(B, "r1"), tags=["lora"], scope=None,
                 ttl_s=3600, reason="x", issued_by=B, created_at="2026-07-25T10:00:00Z",
                 author=A),  # spoofed: signer is A, payload claims issued_by=B
               _offer(wid(A, "o1"), ["lora"], by=A)]
    assert m.active_open_requests(entries, now_ts="2026-07-25T10:30:00Z") == []
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_matches_skips_offer_missing_id():
    """A validly-signed, non-expired offer with no offer_id must not crash
    matches() with a KeyError — it must simply be excluded (fail-closed)."""
    entries = [e(Op.ASSIST_OFFER, tags=["lora"], scope=None, ttl_s=3600,
                 issued_by=A, created_at="2026-07-25T10:00:00Z"),  # no offer_id
               _req(wid(B, "r1"), ["lora"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []


# ---------------------------------------------------------------------------
# Id-shadowing consent-forgery (author-self-certifying ids)
# ---------------------------------------------------------------------------

def test_id_shadowing_offer_rejected():
    """A publishes a well-formed offer oid=author_prefix(A)+"-abcd" that
    matches B's request. Attacker C — a legitimately signed mesh peer —
    then publishes a SHADOW ASSIST_OFFER carrying the EXACT SAME offer_id
    but issued_by=C, hoping the matcher's offers_by_id map collapses by
    bare id (last-writer-wins) so C's shadow satisfies the author check
    (author(C) == issued_by(C)) and hijacks the real A/B match. Since ids
    are now author-self-certifying, C's offer_id doesn't carry C's own
    prefix, so it must be dropped at admission: active_offers must return
    ONLY A's offer, and match_ready for the real mid must be False when C
    posts both accepts (C never legitimately owns oid or the request)."""
    oid = m.author_prefix(A) + "-abcd"
    rid = wid(B, "r1")
    real_offer = _offer(oid, ["lora"], by=A)
    real_req = _req(rid, ["lora"], by=B)
    shadow_offer = e(Op.ASSIST_OFFER, offer_id=oid, tags=["lora"], scope=None,
                     ttl_s=3600, issued_by=C, created_at="2026-07-25T10:00:01Z",
                     author=C)  # published AFTER A's — same id, different author

    entries = [real_offer, real_req, shadow_offer]

    offers = m.active_offers(entries, now_ts="2026-07-25T10:30:00Z")
    assert len(offers) == 1 and offers[0]["issued_by"] == A

    mid = m.match_id(oid, rid)
    forged = entries + [
        e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id=oid, req_id=rid,
          side="offer", issued_by=C, author=C),
        e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id=oid, req_id=rid,
          side="request", issued_by=C, author=C),
    ]
    assert not m.match_ready(forged, mid, now_ts="2026-07-25T10:30:00Z")


def test_wellformed_ids_admitted():
    """An offer/request whose ids carry the correct author prefix ARE
    admitted and produce a match — the guard doesn't reject legitimate
    self-certifying ids."""
    oid, rid = wid(A, "o1"), wid(B, "r1")
    entries = [_offer(oid, ["lora"], by=A), _req(rid, ["lora"], by=B)]
    assert len(m.active_offers(entries, now_ts="2026-07-25T10:30:00Z")) == 1
    assert len(m.active_open_requests(entries, now_ts="2026-07-25T10:30:00Z")) == 1
    ms = m.matches(entries, now_ts="2026-07-25T10:30:00Z")
    assert len(ms) == 1 and ms[0][2] == m.match_id(oid, rid)
