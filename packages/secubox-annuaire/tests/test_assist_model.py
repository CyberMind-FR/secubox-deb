# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from pydantic import ValidationError
from annuaire.model import Op, ASSIST_MODES, AssistRequest, AssistSession

DID = "did:plc:" + "a" * 32


def test_ops_present():
    assert Op.ASSIST_REQUEST == "assist_request"
    assert Op.ASSIST_SESSION_OPEN == "assist_session_open"
    assert Op.ASSIST_CONSOLE_GRANT == "assist_console_grant"


def test_request_valid():
    r = AssistRequest(req_id="r1", center_did=DID, mode="per-incident",
                      scope="firewall", duration_s=1800, reason="help",
                      issued_by=DID)
    assert r.mode in ASSIST_MODES and r.sig is None


def test_request_rejects_bad_mode():
    with pytest.raises(ValidationError):
        AssistRequest(req_id="r1", center_did=DID, mode="root-me",
                      scope="firewall", duration_s=60, reason="x", issued_by=DID)


def test_request_rejects_path_traversal_scope():
    with pytest.raises(ValidationError):
        AssistRequest(req_id="r1", center_did=DID, mode="standing",
                      scope="../../etc", duration_s=60, reason="x", issued_by=DID)


def test_session_requires_64hex_token_hash():
    with pytest.raises(ValidationError):
        AssistSession(session_id="s1", req_id="r1", center_did=DID,
                      token_hash="short", expires_ts="2026-07-25T12:00:00Z",
                      issued_by=DID)
    ok = AssistSession(session_id="s1", req_id="r1", center_did=DID,
                       token_hash="b" * 64, expires_ts="2026-07-25T12:00:00Z",
                       issued_by=DID)
    assert ok.token_hash == "b" * 64


def test_extra_forbidden():
    with pytest.raises(ValidationError):
        AssistRequest(req_id="r1", center_did=DID, mode="standing", scope="dns",
                      duration_s=60, reason="x", issued_by=DID, sneaky=True)
