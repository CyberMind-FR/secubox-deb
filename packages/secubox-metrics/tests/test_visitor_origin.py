# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Unit tests for the VisitorOrigin aggregator pure functions."""
from ipaddress import IPv4Address
from unittest.mock import MagicMock

import pytest
from visitor_origin import VisitorOriginAggregator


CFG = {
    "enabled": True,
    "window_minutes": 60,
    "min_count": 5,
    "top_n": 5,
    "asn_db_path": "/nonexistent/asn.mmdb",
    "nft_table": "secubox_metrics",
    "nft_set": "seen_src",
    "nft_family": "inet",
}


def _agg_with_mock_asn(mapping: dict[str, tuple[int, str]]):
    agg = VisitorOriginAggregator(CFG)

    def fake_lookup(ip):
        return mapping.get(str(ip))

    agg._lookup_asn = fake_lookup  # type: ignore[assignment]
    return agg


def test_aggregate_counts_unique_ips_per_asn():
    agg = _agg_with_mock_asn({
        "1.1.1.1":   (13335, "Cloudflare, Inc."),
        "1.0.0.1":   (13335, "Cloudflare, Inc."),
        "8.8.8.8":   (15169, "Google LLC"),
        "9.9.9.9":   (19281, "Quad9"),
    })
    # Force min_count=1 for this test so all groups survive
    agg.cfg = dict(CFG, min_count=1)
    entries = agg._aggregate([IPv4Address("1.1.1.1"),
                              IPv4Address("1.0.0.1"),
                              IPv4Address("8.8.8.8"),
                              IPv4Address("9.9.9.9")])
    counts = {e["asn"]: e["count"] for e in entries}
    assert counts == {13335: 2, 15169: 1, 19281: 1}


def test_aggregate_threshold_keeps_equal_drops_below():
    agg = _agg_with_mock_asn({
        "1.1.1.1": (13335, "Cloudflare"),
        "1.0.0.1": (13335, "Cloudflare"),
        "1.0.0.2": (13335, "Cloudflare"),
        "1.0.0.3": (13335, "Cloudflare"),
        "1.0.0.4": (13335, "Cloudflare"),  # 5 distinct -> kept
        "8.8.8.8": (15169, "Google"),
        "8.8.4.4": (15169, "Google"),
        "8.8.0.1": (15169, "Google"),
        "8.8.0.2": (15169, "Google"),       # 4 distinct -> dropped
    })
    entries = agg._aggregate([IPv4Address(s) for s in [
        "1.1.1.1", "1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4",
        "8.8.8.8", "8.8.4.4", "8.8.0.1", "8.8.0.2",
    ]])
    asns = {e["asn"] for e in entries}
    assert 13335 in asns
    assert 15169 not in asns


def test_aggregate_top_n_and_tiebreak_by_asn():
    agg = _agg_with_mock_asn({
        f"10.0.0.{i}": (100 + (i % 3), f"org{i % 3}") for i in range(1, 16)
    })
    agg.cfg = dict(CFG, top_n=2, min_count=1)
    entries = agg._aggregate([IPv4Address(f"10.0.0.{i}") for i in range(1, 16)])
    assert len(entries) == 2
    # All three ASNs (100, 101, 102) have count=5; tie must resolve to smallest ASN first.
    assert entries[0]["asn"] == 100
    assert entries[1]["asn"] == 101
    assert entries[0]["count"] == 5
    assert entries[1]["count"] == 5


def test_lookup_asn_returns_none_for_private():
    agg = VisitorOriginAggregator(CFG)
    assert agg._lookup_asn(IPv4Address("10.0.0.1")) is None
    assert agg._lookup_asn(IPv4Address("192.168.1.1")) is None
    assert agg._lookup_asn(IPv4Address("127.0.0.1")) is None


def test_lookup_asn_reopens_on_mtime_change(monkeypatch, tmp_path):
    """If the mmdb file's mtime changes between calls, the handle is reopened."""
    db_path = tmp_path / "asn.mmdb"
    db_path.write_bytes(b"v1")
    cfg = dict(CFG, asn_db_path=str(db_path))
    agg = VisitorOriginAggregator(cfg)

    open_calls = []

    class FakeMmdb:
        def __init__(self, n): self.n = n
        def get(self, _): return None
        def close(self): pass

    def fake_open(path):
        open_calls.append(path)
        return FakeMmdb(len(open_calls))

    monkeypatch.setattr("visitor_origin.maxminddb",
                        type("M", (), {"open_database": staticmethod(fake_open)}))

    # First lookup opens v1
    agg._lookup_asn(IPv4Address("1.1.1.1"))
    assert len(open_calls) == 1

    # No file change → no reopen
    agg._lookup_asn(IPv4Address("1.1.1.2"))
    assert len(open_calls) == 1

    # Bump mtime → reopen on next call
    import os
    new_mtime = db_path.stat().st_mtime + 100
    os.utime(db_path, (new_mtime, new_mtime))
    agg._lookup_asn(IPv4Address("1.1.1.3"))
    assert len(open_calls) == 2


def test_refresh_disabled_returns_disabled():
    agg = VisitorOriginAggregator(dict(CFG, enabled=False))
    import asyncio
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False
    assert out["entries"] == []


def test_refresh_missing_mmdb_returns_disabled(tmp_path):
    agg = VisitorOriginAggregator(dict(CFG, asn_db_path=str(tmp_path / "missing.mmdb")))
    import asyncio
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False


def test_refresh_handles_nft_failure(monkeypatch, tmp_path):
    # Pretend mmdb exists so we reach _read_nft_set
    fake_db = tmp_path / "asn.mmdb"
    fake_db.write_bytes(b"\x00")  # truthy existence
    agg = VisitorOriginAggregator(dict(CFG, asn_db_path=str(fake_db)))
    # Force maxminddb import path to succeed without a real db by mocking _lookup_asn
    agg._lookup_asn = lambda ip: None  # type: ignore[assignment]
    # Ensure module-level maxminddb guard passes even if package is not installed
    monkeypatch.setattr("visitor_origin.maxminddb", object())
    monkeypatch.setattr(
        "visitor_origin.subprocess.run",
        lambda *a, **kw: MagicMock(returncode=1, stdout=""),
    )
    import asyncio
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is True
    assert out["entries"] == []
