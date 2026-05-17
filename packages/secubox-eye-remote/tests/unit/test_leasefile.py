# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: dnsmasq lease file parser tests."""
from pathlib import Path

from api.lib.leasefile import Lease, parse_leases


def test_parse_two_active_leases():
    src = (
        "1747500000 02:fb:00:00:11:03 10.55.0.11 eye-rpiz 01:02:fb:00:00:11:03\n"
        "1747503600 02:fb:00:00:d2:7f 10.55.0.12 eye-pi4b 01:02:fb:00:00:d2:7f\n"
    )
    leases = parse_leases(src)
    by_mac = {l.mac: l for l in leases}

    rpiz = by_mac["02:fb:00:00:11:03"]
    assert rpiz.expiry == 1747500000
    assert rpiz.ip == "10.55.0.11"
    assert rpiz.hostname == "eye-rpiz"
    assert rpiz.client_id == "01:02:fb:00:00:11:03"

    pi4b = by_mac["02:fb:00:00:d2:7f"]
    assert pi4b.expiry == 1747503600
    assert pi4b.ip == "10.55.0.12"
    assert pi4b.hostname == "eye-pi4b"
    assert pi4b.client_id == "01:02:fb:00:00:d2:7f"


def test_parse_handles_missing_hostname():
    src = "1747500000 02:fb:00:00:11:03 10.55.0.11 * 01:02:fb:00:00:11:03\n"
    [l] = parse_leases(src)
    assert l.hostname is None


def test_parse_ignores_blank_and_short_lines():
    src = "\n\nbroken-line\n1747500000 02:fb:00:00:11:03 10.55.0.11 a id\n"
    leases = parse_leases(src)
    assert len(leases) == 1


def test_parse_path_round_trip(tmp_path: Path):
    p = tmp_path / "leases"
    p.write_text("1747500000 02:fb:00:00:11:03 10.55.0.11 a id\n")
    [l] = parse_leases(p.read_text())
    assert l.ip == "10.55.0.11"
    assert l.expiry == 1747500000


def test_parse_skips_lines_with_non_numeric_expiry():
    src = (
        "notanint 02:fb:00:00:11:03 10.55.0.11 host id\n"
        "1747500000 02:fb:00:00:11:03 10.55.0.11 host id\n"
    )
    leases = parse_leases(src)
    # First line is dropped (non-numeric expiry); second line survives.
    assert len(leases) == 1
    assert leases[0].expiry == 1747500000
