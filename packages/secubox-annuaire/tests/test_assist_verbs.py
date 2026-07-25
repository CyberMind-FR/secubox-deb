# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
import pytest
from annuaire.log import Journal
from annuaire.crypto import canonical_bytes, verify, public_from_private, did_from_pubkey
from annuaire import verbs, assist
from annuaire.model import Op


def _key():
    priv = os.urandom(32)
    did = did_from_pubkey(public_from_private(priv))
    return priv, did


def _journal(tmp_path):
    return Journal(str(tmp_path / "journal.db"))


def test_request_is_signed_and_appended(tmp_path):
    j = _journal(tmp_path)
    box_priv, box_did = _key()
    _, center_did = _key()
    entry = verbs.assist_request(j, box_priv, center_did, "per-incident",
                                 "firewall", 1800, "help me", req_id="r1")
    assert entry.op == Op.ASSIST_REQUEST.value
    payload = entry.payload
    box_pub = public_from_private(box_priv).hex()
    assert verify(box_pub, canonical_bytes(payload), entry.sig)


def test_session_open_blocked_without_accept(tmp_path):
    j = _journal(tmp_path)
    box_priv, box_did = _key()
    _, center_did = _key()
    verbs.assist_request(j, box_priv, center_did, "per-incident", "dns", 600, "x", req_id="r1")
    with pytest.raises(ValueError):
        verbs.assist_session_open(j, box_priv, "r1", center_did,
                                  token_hash="a" * 64,
                                  expires_ts="2999-01-01T00:00:00Z",
                                  session_id="s1")


def test_full_open_after_accept(tmp_path):
    j = _journal(tmp_path)
    box_priv, box_did = _key()
    center_priv, center_did = _key()
    verbs.assist_request(j, box_priv, center_did, "per-incident", "dns", 600, "x", req_id="r1")
    verbs.assist_accept(j, center_priv, "r1")
    entry = verbs.assist_session_open(j, box_priv, "r1", center_did,
                                      token_hash="a" * 64,
                                      expires_ts="2999-01-01T00:00:00Z",
                                      session_id="s1")
    assert entry.op == Op.ASSIST_SESSION_OPEN.value
    s = assist.active_session(list(j.iter_entries()), box_did, now_ts="2026-07-25T00:00:00Z")
    assert s and s["session_id"] == "s1"
