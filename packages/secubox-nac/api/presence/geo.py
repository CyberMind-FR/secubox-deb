# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — cross-plane presence geo/provenance enricher
(Project B, #820, Task 2).

`enrich_origin(ip_or_identity, plane)` classifies a presence's origin:

- A PUBLIC IP → `provenance="geo"`; `geo_cc` from the MaxMind GeoLite2-Country
  mmdb, `geo_asn`/`geo_org` from the GeoLite2-ASN mmdb, when the respective
  reader is available and the lookup succeeds (best-effort — a missing mmdb
  or a failed lookup leaves the geo fields empty but `provenance` stays
  `"geo"`, since the IP itself is public).
- A PRIVATE/loopback/link-local IP → `provenance="private"`, no geo.
- A non-IP identity (e.g. a `mac_hash`) → `provenance` derived from `plane`:
  `lan`->"lan", `wg`/`kbin`->"tunnel", `mesh`->"mesh", anything else
  ->"unknown". No geo lookup is attempted for non-IP identities.
- A malformed/empty/None input → `provenance="unknown"`, no geo, never
  raises.

Reuses the exact reader pattern already in production:
`packages/secubox-waf/api/main.py` (`geoip2.database.Reader` against
`GeoLite2-Country.mmdb`, `AddressNotFoundError` handled) and
`packages/secubox-metrics/api/visitor_origin.py` (`maxminddb.open_database`
against `GeoLite2-ASN.mmdb`, `autonomous_system_number`/
`autonomous_system_organization`). Both third-party libraries are imported
lazily (inside the reader-opening functions) so this module — and anything
importing it — stays import-safe even when `geoip2`/`maxminddb` are not
installed in the running environment; the readers are opened once, on
first real use, and cached in module state (`_country_reader`/
`_asn_reader`). Tests inject fakes by setting those module globals (or by
monkeypatching `_get_country_reader`/`_get_asn_reader`) directly — no real
mmdb file or library is required to exercise the enrichment logic.

Pure stdlib + optional geoip2/maxminddb. No I/O at import time.
"""
from __future__ import annotations

import ipaddress

COUNTRY_DB_PATH = "/var/lib/secubox/geoip/GeoLite2-Country.mmdb"
ASN_DB_PATH = "/var/lib/secubox/geoip/GeoLite2-ASN.mmdb"

# Lazily-opened, cached readers (module state). `None` means "not opened
# yet"; tests may pre-set these to a fake reader object to short-circuit
# the real open, or monkeypatch the `_get_*_reader` functions below.
_country_reader = None
_asn_reader = None

# Non-IP identity -> provenance, keyed by collection plane.
_PLANE_PROVENANCE = {
    "lan": "lan",
    "wg": "tunnel",
    "kbin": "tunnel",
    "mesh": "mesh",
}


def _get_country_reader():
    """Return the cached GeoLite2-Country reader, opening it on first use.

    Fail-safe: any import or open error leaves the reader unset and returns
    `None` — never raises.
    """
    global _country_reader
    if _country_reader is not None:
        return _country_reader
    try:
        import geoip2.database
    except ImportError:
        return None
    try:
        _country_reader = geoip2.database.Reader(COUNTRY_DB_PATH)
    except Exception:
        return None
    return _country_reader


def _get_asn_reader():
    """Return the cached GeoLite2-ASN (maxminddb) reader, opening it lazily.

    Fail-safe: any import or open error leaves the reader unset and returns
    `None` — never raises.
    """
    global _asn_reader
    if _asn_reader is not None:
        return _asn_reader
    try:
        import maxminddb
    except ImportError:
        return None
    try:
        _asn_reader = maxminddb.open_database(ASN_DB_PATH)
    except Exception:
        return None
    return _asn_reader


def _lookup_country(ip_str: str) -> str | None:
    """Best-effort ISO country code for a public IP. Never raises.

    The whole body — including obtaining the reader itself — is guarded:
    a misbehaving getter (e.g. an open failing in an unexpected way) must
    degrade to "no country" exactly like a missing reader would.
    """
    try:
        reader = _get_country_reader()
        if reader is None:
            return None
        response = reader.country(ip_str)
        cc = getattr(getattr(response, "country", None), "iso_code", None)
        return cc or None
    except Exception:
        # Covers geoip2.errors.AddressNotFoundError and any other failure
        # from a fake/real reader (or getter) alike.
        return None


def _lookup_asn(ip_str: str) -> tuple[str | None, str | None]:
    """Best-effort `(geo_asn, geo_org)` for a public IP. Never raises."""
    try:
        reader = _get_asn_reader()
        if reader is None:
            return None, None
        record = reader.get(ip_str)
        if not record:
            return None, None
        asn = record.get("autonomous_system_number")
        org = record.get("autonomous_system_organization") or None
        if asn is None:
            return None, org
        return f"AS{asn}", org
    except Exception:
        return None, None


def enrich_origin(ip_or_identity: str, plane: str) -> dict:
    """Classify a presence's origin into `{geo_cc, geo_asn, geo_org, provenance}`.

    Fail-safe by construction: no branch here raises — a bad/None input, a
    missing plane, or an unopenable mmdb all fall through to a populated-but-
    empty result with `provenance` always set.
    """
    result = {"geo_cc": None, "geo_asn": None, "geo_org": None, "provenance": "unknown"}

    if not ip_or_identity or not isinstance(ip_or_identity, str):
        return result

    try:
        ip = ipaddress.ip_address(ip_or_identity)
    except ValueError:
        ip = None

    if ip is None:
        # Not an IP at all — a plane-derived identity (mac_hash, persona…).
        result["provenance"] = _PLANE_PROVENANCE.get(plane, "unknown")
        return result

    if ip.is_private or ip.is_loopback or ip.is_link_local:
        result["provenance"] = "private"
        return result

    # Public IP: provenance is "geo" regardless of mmdb availability — geo
    # fields are populated only when the respective reader/lookup succeeds.
    result["provenance"] = "geo"
    result["geo_cc"] = _lookup_country(ip_or_identity)
    asn, org = _lookup_asn(ip_or_identity)
    result["geo_asn"] = asn
    result["geo_org"] = org
    return result
