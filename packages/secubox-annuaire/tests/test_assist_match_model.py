# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from pydantic import ValidationError
from annuaire.model import (Op, AssistOffer, AssistOpenRequest, AssistMatchAccept)

DID = "did:plc:" + "a" * 32


def test_ops_present():
    assert Op.ASSIST_OFFER == "assist_offer"
    assert Op.ASSIST_REQUEST_OPEN == "assist_request_open"
    assert Op.ASSIST_MATCH_ACCEPT == "assist_match_accept"


def test_offer_valid_and_extra_forbidden():
    o = AssistOffer(offer_id="o1", tags=["lora", "meshtastic"], scope=None,
                    ttl_s=1800, issued_by=DID)
    assert o.tags == ["lora", "meshtastic"] and o.sig is None
    with pytest.raises(ValidationError):
        AssistOffer(offer_id="o1", tags=["x"], scope=None, ttl_s=1800,
                    issued_by=DID, sneaky=True)


def test_open_request_reason_bounds():
    AssistOpenRequest(req_id="r1", tags=["lora"], scope="dns", ttl_s=600,
                      reason="need help", issued_by=DID)
    with pytest.raises(ValidationError):
        AssistOpenRequest(req_id="r1", tags=["lora"], scope="dns", ttl_s=600,
                          reason="", issued_by=DID)


def test_match_accept_side_and_hexid():
    AssistMatchAccept(match_id="b" * 64, offer_id="o1", req_id="r1",
                      side="offer", issued_by=DID)
    with pytest.raises(ValidationError):
        AssistMatchAccept(match_id="short", offer_id="o1", req_id="r1",
                          side="offer", issued_by=DID)
    with pytest.raises(ValidationError):
        AssistMatchAccept(match_id="b" * 64, offer_id="o1", req_id="r1",
                          side="bogus", issued_by=DID)
