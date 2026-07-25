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


def test_malformed_ttl_fails_closed():
    entries = [_offer("o1", ["lora"], ttl="not-a-number"), _req("r1", ["lora"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
    assert m.active_offers(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_malformed_created_at_fails_closed():
    entries = [_offer("o1", ["lora"], at="garbage"), _req("r1", ["lora"])]
    assert m.matches(entries, now_ts="2026-07-25T10:30:00Z") == []
    assert m.active_offers(entries, now_ts="2026-07-25T10:30:00Z") == []


def test_match_ready_needs_both_sides():
    mid = m.match_id("o1", "r1")
    base = [_offer("o1", ["lora"]), _req("r1", ["lora"])]
    only_offer = base + [e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1",
                           req_id="r1", side="offer", issued_by=A)]
    assert not m.match_ready(only_offer, mid, now_ts="2026-07-25T10:30:00Z")
    both = only_offer + [e(Op.ASSIST_MATCH_ACCEPT, match_id=mid, offer_id="o1",
                           req_id="r1", side="request", issued_by=B)]
    assert m.match_ready(both, mid, now_ts="2026-07-25T10:30:00Z")
