# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
from annuaire.log import Journal
from annuaire.crypto import canonical_bytes, verify, public_from_private, did_from_pubkey
from annuaire import verbs, assist_match as m
from annuaire.model import Op, now_rfc3339


def _key():
    p = os.urandom(32)
    return p, did_from_pubkey(public_from_private(p))


def test_offer_signed_and_appended(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    priv, did = _key()
    oid = m.author_prefix(did) + "-o1"
    entry = verbs.assist_offer(j, priv, ["lora"], None, 1800, offer_id=oid)
    assert entry.op == Op.ASSIST_OFFER.value
    assert verify(public_from_private(priv).hex(), canonical_bytes(entry.payload), entry.sig)


def test_full_match_ready(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    ap, ad = _key(); bp, bd = _key()
    oid = m.author_prefix(ad) + "-o1"
    rid = m.author_prefix(bd) + "-r1"
    verbs.assist_offer(j, ap, ["lora"], None, 3600, offer_id=oid)
    verbs.assist_open_request(j, bp, ["lora"], None, 3600, "help", req_id=rid)
    verbs.assist_match_accept(j, ap, oid, rid, "offer")
    verbs.assist_match_accept(j, bp, oid, rid, "request")
    entries = list(j.iter_entries())
    # exercise the codebase's real "now" shape (model.now_rfc3339()'s
    # isoformat rendering), not a hand-picked Z-suffixed fixture string.
    assert m.match_ready(entries, m.match_id(oid, rid), now_ts=now_rfc3339())
