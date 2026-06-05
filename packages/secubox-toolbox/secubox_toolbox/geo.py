# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""GeoIP : IP → country (flag emoji) + ASN + org. With SQLite cache."""
from __future__ import annotations

import logging
import socket
import sqlite3
import time
from pathlib import Path

log = logging.getLogger("secubox.toolbox.geo")

DB = Path("/var/lib/secubox/toolbox/toolbox.db")
COUNTRY_MMDB = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
COUNTRY_LEGACY = "/usr/share/GeoIP/GeoIP.dat"
ASN_MMDB = "/var/lib/GeoIP/GeoLite2-ASN.mmdb"

SCHEMA = """
CREATE TABLE IF NOT EXISTS geo_cache (
    key TEXT PRIMARY KEY,
    country_iso TEXT,
    country_name TEXT,
    asn INTEGER,
    asn_org TEXT,
    ts INTEGER NOT NULL
);
"""

_COUNTRY_READER = None
_ASN_READER = None
_GEOIP_LEGACY = None


def _init_readers() -> None:
    global _COUNTRY_READER, _ASN_READER, _GEOIP_LEGACY
    if _COUNTRY_READER is None:
        try:
            import geoip2.database
            if Path(COUNTRY_MMDB).exists():
                _COUNTRY_READER = geoip2.database.Reader(COUNTRY_MMDB)
        except Exception as e:
            log.debug("country mmdb unavailable: %s", e)
        # Fallback : legacy GeoIP.dat via pygeoip / GeoIP module
        if _COUNTRY_READER is None and Path(COUNTRY_LEGACY).exists():
            try:
                import GeoIP  # python3-geoip-dev (optionnel)
                _GEOIP_LEGACY = GeoIP.open(COUNTRY_LEGACY, GeoIP.GEOIP_STANDARD)
            except Exception:
                # Try the cli wrapper
                pass
    if _ASN_READER is None and Path(ASN_MMDB).exists():
        try:
            import geoip2.database
            _ASN_READER = geoip2.database.Reader(ASN_MMDB)
        except Exception as e:
            log.debug("asn mmdb unavailable: %s", e)


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB, timeout=2)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def iso_to_flag(iso: str) -> str:
    """Convert ISO-3166 alpha-2 (FR, US, ...) → flag emoji via regional indicator letters."""
    if not iso or len(iso) != 2 or not iso.isalpha():
        return "🏳"
    iso = iso.upper()
    return chr(0x1F1E6 + ord(iso[0]) - ord("A")) + chr(0x1F1E6 + ord(iso[1]) - ord("A"))


def _resolve_host_to_ip(host: str) -> str | None:
    try:
        # IP literal ? return as-is
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return None


def lookup(key: str) -> dict:
    """Returns {country_iso, country_name, flag, asn, asn_org} for an IP or host.
    Uses 24h cache. Empty dict on full miss."""
    _init_readers()
    # cache hit ?
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM geo_cache WHERE key=? AND ts > ?",
                (key, int(time.time()) - 86400),
            ).fetchone()
        if row:
            return {
                "country_iso": row["country_iso"] or "",
                "country_name": row["country_name"] or "",
                "flag": iso_to_flag(row["country_iso"] or ""),
                "asn": row["asn"] or 0,
                "asn_org": row["asn_org"] or "",
            }
    except Exception:
        pass

    ip = _resolve_host_to_ip(key)
    if not ip:
        return {}

    iso = ""
    name = ""
    asn = 0
    asn_org = ""

    if _COUNTRY_READER is not None:
        try:
            r = _COUNTRY_READER.country(ip)
            iso = (r.country.iso_code or "").upper()
            name = r.country.name or ""
        except Exception:
            pass
    elif _GEOIP_LEGACY is not None:
        try:
            iso = (_GEOIP_LEGACY.country_code_by_addr(ip) or "").upper()
            name = _GEOIP_LEGACY.country_name_by_addr(ip) or ""
        except Exception:
            pass

    if _ASN_READER is not None:
        try:
            r = _ASN_READER.asn(ip)
            asn = r.autonomous_system_number or 0
            asn_org = r.autonomous_system_organization or ""
        except Exception:
            pass

    # cache write
    try:
        with _conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO geo_cache(key, country_iso, country_name, asn, asn_org, ts) "
                "VALUES (?,?,?,?,?,?)",
                (key, iso, name, asn, asn_org, int(time.time())),
            )
    except Exception:
        pass

    return {
        "country_iso": iso,
        "country_name": name,
        "flag": iso_to_flag(iso) if iso else "",
        "asn": asn,
        "asn_org": asn_org,
    }


def enrich_hosts(hosts: list[str]) -> dict[str, dict]:
    """Returns {host: {country_iso, flag, asn, asn_org, ...}, ...}"""
    return {h: lookup(h) for h in hosts}
