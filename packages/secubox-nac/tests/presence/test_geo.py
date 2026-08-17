# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for `presence.geo.enrich_origin`
(Project B, Task 2, #820).

Injects fake country/ASN readers via the module's cached globals (mirrors
how `geoip2.database.Reader`/`maxminddb.open_database` objects behave) so
these tests never require the real `geoip2`/`maxminddb` libraries or an
actual mmdb file on disk.
"""

import pytest


class _FakeCountryResponse:
    def __init__(self, iso_code):
        class _C:
            pass
        self.country = _C()
        self.country.iso_code = iso_code


class _FakeCountryReader:
    """Mirrors `geoip2.database.Reader`'s `.country(ip)` interface."""

    def __init__(self, cc="US"):
        self.cc = cc

    def country(self, ip_str):
        return _FakeCountryResponse(self.cc)


class _RaisingCountryReader:
    def country(self, ip_str):
        raise RuntimeError("mmdb corrupt")


class _FakeAsnReader:
    """Mirrors `maxminddb`'s `.get(ip)` interface (returns a dict or None)."""

    def __init__(self, asn=15169, org="Google"):
        self.asn = asn
        self.org = org

    def get(self, ip_str):
        return {
            "autonomous_system_number": self.asn,
            "autonomous_system_organization": self.org,
        }


@pytest.fixture(autouse=True)
def _reset_readers(monkeypatch):
    """Every test starts from a clean (unopened) reader-cache state."""
    from api.presence import geo
    monkeypatch.setattr(geo, "_country_reader", None)
    monkeypatch.setattr(geo, "_asn_reader", None)
    yield


def test_public_ip_geo(monkeypatch):
    from api.presence import geo

    monkeypatch.setattr(geo, "_country_reader", _FakeCountryReader("US"))
    monkeypatch.setattr(geo, "_asn_reader", _FakeAsnReader(15169, "Google"))

    result = geo.enrich_origin("8.8.8.8", "wan")

    assert result["provenance"] == "geo"
    assert result["geo_cc"] == "US"
    assert result["geo_asn"] == "AS15169"
    assert result["geo_org"] == "Google"


def test_private_ip():
    from api.presence import geo

    result = geo.enrich_origin("10.0.0.5", "wan")

    assert result["provenance"] == "private"
    assert not result["geo_cc"]
    assert not result["geo_asn"]


def test_loopback_and_link_local_ip():
    from api.presence import geo

    assert geo.enrich_origin("127.0.0.1", "wan")["provenance"] == "private"
    assert geo.enrich_origin("169.254.1.1", "wan")["provenance"] == "private"


def test_tunnel_identity():
    from api.presence import geo

    result = geo.enrich_origin("a1b2c3d4e5f6", "kbin")

    assert result["provenance"] == "tunnel"
    assert not result["geo_cc"]
    assert not result["geo_asn"]

    # `wg` plane also maps to "tunnel".
    assert geo.enrich_origin("a1b2c3d4e5f6", "wg")["provenance"] == "tunnel"


def test_lan_and_mesh_identity():
    from api.presence import geo

    assert geo.enrich_origin("aa:bb:cc:00:00:01", "lan")["provenance"] == "lan"
    assert geo.enrich_origin("did:plc:abc123", "mesh")["provenance"] == "mesh"


def test_missing_mmdb_failsafe(monkeypatch):
    from api.presence import geo

    # Readers stay None (unopenable / not installed in this environment) —
    # enrich_origin must not raise, and provenance must still be set.
    monkeypatch.setattr(geo, "_get_country_reader", lambda: None)
    monkeypatch.setattr(geo, "_get_asn_reader", lambda: None)

    result = geo.enrich_origin("8.8.8.8", "wan")

    assert result["provenance"] == "geo"
    assert result["geo_cc"] is None
    assert result["geo_asn"] is None
    assert result["geo_org"] is None


def test_reader_raises_failsafe(monkeypatch):
    from api.presence import geo

    monkeypatch.setattr(geo, "_country_reader", _RaisingCountryReader())
    monkeypatch.setattr(geo, "_get_asn_reader", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    # Must not raise even though both readers misbehave.
    result = geo.enrich_origin("1.1.1.1", "wan")

    assert result["provenance"] == "geo"
    assert result["geo_cc"] is None
    assert result["geo_asn"] is None


def test_garbage_input():
    from api.presence import geo

    empty = geo.enrich_origin("", "wan")
    assert empty["provenance"] == "unknown"
    assert not empty["geo_cc"]

    none_input = geo.enrich_origin(None, "wan")
    assert none_input["provenance"] == "unknown"

    non_ip_wan = geo.enrich_origin("not-an-ip-or-mac", "wan")
    assert non_ip_wan["provenance"] == "unknown"
    assert not non_ip_wan["geo_cc"]
