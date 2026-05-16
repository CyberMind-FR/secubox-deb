# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: eye-remote reservations parser tests."""
from pathlib import Path

import pytest

from api.lib.reservations import (
    Reservation,
    append_reservation,
    filter_active,
    parse_reservations,
    serialize_reservation,
)


def test_parse_single_line():
    src = "dhcp-host=02:fb:00:00:11:03,10.55.0.11,eye-1000000011f3b403,24h\n"
    [r] = parse_reservations(src)
    assert r.mac == "02:fb:00:00:11:03"
    assert r.ip == "10.55.0.11"
    assert r.hostname == "eye-1000000011f3b403"
    assert r.lease_time == "24h"


def test_parse_skips_comments_and_blank():
    src = "# comment\n\ndhcp-host=02:fb:00:00:11:03,10.55.0.11,a,24h\n# trailing\n"
    rs = parse_reservations(src)
    assert len(rs) == 1
    assert rs[0].mac == "02:fb:00:00:11:03"


def test_parse_rejects_short_mac():
    with pytest.raises(ValueError, match="invalid MAC"):
        parse_reservations("dhcp-host=02:fb,10.55.0.11,a,24h\n")


def test_serialize_round_trip():
    r = Reservation(
        mac="02:fb:00:00:d2:7f",
        ip="10.55.0.12",
        hostname="eye-00000000d253b17f",
        lease_time="24h",
    )
    assert (
        serialize_reservation(r)
        == "dhcp-host=02:fb:00:00:d2:7f,10.55.0.12,eye-00000000d253b17f,24h"
    )


def test_append_reservation_is_idempotent(tmp_path: Path):
    f = tmp_path / "reservations.conf"
    f.write_text("")
    r = Reservation("02:fb:00:00:11:03", "10.55.0.11", "eye-x", "24h")
    assert append_reservation(f, r) is True
    assert append_reservation(f, r) is False
    assert f.read_text().count("dhcp-host=") == 1


def test_append_reservation_rejects_mac_conflict(tmp_path: Path):
    f = tmp_path / "reservations.conf"
    f.write_text("dhcp-host=02:fb:00:00:11:03,10.55.0.11,old,24h\n")
    with pytest.raises(ValueError, match="conflict"):
        append_reservation(
            f,
            Reservation("02:fb:00:00:11:03", "10.55.0.99", "new", "24h"),
        )


def test_filter_active_is_case_insensitive():
    rs = [
        Reservation("02:FB:00:00:11:03", "10.55.0.11", "rpiz", "24h"),
        Reservation("02:fb:00:00:d2:7f", "10.55.0.12", "pi4b", "24h"),
        Reservation("02:fb:00:00:99:99", "10.55.0.20", "absent", "24h"),
    ]
    active = filter_active(rs, ["02:fb:00:00:11:03", "02:FB:00:00:D2:7F"])
    macs = {r.mac for r in active}
    assert macs == {"02:FB:00:00:11:03", "02:fb:00:00:d2:7f"}


def test_append_reservation_handles_missing_trailing_newline(tmp_path: Path):
    f = tmp_path / "reservations.conf"
    f.write_text("dhcp-host=02:fb:00:00:11:03,10.55.0.11,a,24h")  # NO trailing \n
    r = Reservation("02:fb:00:00:11:04", "10.55.0.12", "b", "24h")
    assert append_reservation(f, r) is True

    # Both reservations must be parseable after the append
    parsed = parse_reservations(f.read_text())
    assert len(parsed) == 2
    assert {p.mac for p in parsed} == {
        "02:fb:00:00:11:03",
        "02:fb:00:00:11:04",
    }


def test_append_reservation_dedupes_case_insensitively(tmp_path: Path):
    f = tmp_path / "reservations.conf"
    f.write_text("dhcp-host=02:FB:00:00:11:03,10.55.0.11,a,24h\n")
    # Same MAC in lowercase, same record otherwise → must be detected as duplicate
    r = Reservation("02:fb:00:00:11:03", "10.55.0.11", "a", "24h")
    with pytest.raises(ValueError, match="conflict"):
        append_reservation(f, r)
