# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: eye-remote IP auto-assignment tests."""
import pytest

from api.lib.assign import assign_ip
from api.lib.reservations import Reservation


def test_assigns_first_free_starting_at_11():
    rs: list[Reservation] = []
    assert assign_ip(rs) == "10.55.0.11"


def test_skips_existing():
    rs = [
        Reservation("02:fb:00:00:11:03", "10.55.0.11", "a", "24h"),
        Reservation("02:fb:00:00:11:04", "10.55.0.12", "b", "24h"),
    ]
    assert assign_ip(rs) == "10.55.0.13"


def test_fills_gaps():
    rs = [
        Reservation("02:fb:00:00:11:03", "10.55.0.11", "a", "24h"),
        Reservation("02:fb:00:00:11:04", "10.55.0.13", "b", "24h"),
    ]
    assert assign_ip(rs) == "10.55.0.12"


def test_exhausted_pool_raises():
    rs = [
        Reservation(
            mac=f"02:fb:00:00:00:{i:02x}",
            ip=f"10.55.0.{i}",
            hostname=f"h{i}",
            lease_time="24h",
        )
        for i in range(11, 251)
    ]
    with pytest.raises(RuntimeError, match="exhausted"):
        assign_ip(rs)


def test_ignores_non_subnet_reservations():
    rs = [
        Reservation("aa:bb:cc:dd:ee:ff", "192.168.1.10", "foreign", "24h"),
        Reservation("02:fb:00:00:11:03", "10.55.0.20", "ours", "24h"),
    ]
    # The foreign reservation should not block .11 from being assigned.
    assert assign_ip(rs) == "10.55.0.11"


def test_ignores_malformed_octet_in_subnet():
    rs = [
        Reservation("02:fb:00:00:99:99", "10.55.0.abc", "broken", "24h"),
        # Real reservation that should NOT be displaced by the bad one
    ]
    assert assign_ip(rs) == "10.55.0.11"
