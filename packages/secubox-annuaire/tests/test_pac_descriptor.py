# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-annuaire :: test_pac_descriptor
CyberMind — https://cybermind.fr
"""

from annuaire.model import ServiceOffer, PacDescriptor
from annuaire.crypto import canonical_bytes
import pytest


def _offer(**kw):
    return ServiceOffer(service_id="a1", provider="did:plc:"+"0"*32,
                        name="svc", kind="api", endpoint="http://10.10.0.1/x", **kw)


def test_pac_parses_and_validates():
    o = _offer(pac=PacDescriptor(match=["*.onion"], proxy="socks5"))
    assert o.pac.match == ["*.onion"] and o.pac.proxy == "socks5"


def test_pac_rejects_bad_proxy():
    with pytest.raises(Exception):
        PacDescriptor(match=["x"], proxy="tunnel")


def test_pac_rejects_empty_match():
    with pytest.raises(Exception):
        PacDescriptor(match=[], proxy="socks5")


def test_pacless_offer_is_byte_stable():
    # An offer with no pac must serialize identically to the pre-field baseline.
    # created_at is pinned so the two independent instances are byte-comparable
    # (ServiceOffer.created_at otherwise defaults to datetime.now(), which would
    # make this assertion flaky regardless of the pac field under test).
    fixed_ts = "2026-01-01T00:00:00+00:00"
    o = _offer(created_at=fixed_ts)
    payload = o.model_dump(exclude_none=True)
    assert "pac" not in payload
    assert canonical_bytes(payload) == canonical_bytes(_offer(created_at=fixed_ts).model_dump(exclude_none=True))
