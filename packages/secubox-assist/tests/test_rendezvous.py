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


def e(op, author=None, **p):
    """Build a journal-entry dict. `author` is the authenticated signer field
    (as the real Journal sets it) — defaults to the payload's `issued_by`."""
    if author is None:
        author = p.get("issued_by")
    return {"op": op.value, "author": author, "payload": p}


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
