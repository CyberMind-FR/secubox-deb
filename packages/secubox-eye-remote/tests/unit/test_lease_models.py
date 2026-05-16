# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: lease Pydantic model smoke tests."""
import pytest
from pydantic import ValidationError

from api.models.lease import LeaseEvent, LeaseRecord


def test_lease_event_accepts_lifecycle_actions():
    for a in ("add", "old", "del", "discover"):
        LeaseEvent(action=a, mac="02:fb:00:00:11:03", ip="10.55.0.11")


def test_lease_event_rejects_unknown_action():
    with pytest.raises(ValidationError):
        LeaseEvent(action="bogus", mac="02:fb:00:00:11:03", ip="10.55.0.11")


def test_lease_event_rejects_malformed_mac():
    with pytest.raises(ValidationError):
        LeaseEvent(action="add", mac="not-a-mac", ip="10.55.0.11")


def test_lease_record_round_trip():
    rec = LeaseRecord(
        mac="02:fb:00:00:11:03",
        ip="10.55.0.11",
        hostname="eye-rpiz",
        serial="1000000011f3b403",
        last_seen=1747500000,
        approved=True,
    )
    assert rec.model_dump()["approved"] is True


def test_lease_record_approved_default_true():
    rec = LeaseRecord(
        mac="02:fb:00:00:11:03",
        ip="10.55.0.11",
        hostname=None,
        serial=None,
        last_seen=None,
    )
    assert rec.approved is True
