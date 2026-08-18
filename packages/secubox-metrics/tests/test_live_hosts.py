# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Unit tests for LiveHosts ring buffer + parsing + filter + aggregation."""
import asyncio
from unittest.mock import patch, MagicMock

from live_hosts import LiveHostsAggregator


CFG = {
    "enabled": True,
    "window_minutes": 60,
    "top_n": 5,
    "haproxy_socket": "/nonexistent.sock",
    "frontend_filter": "*",
}


def _drive(agg, totals_sequence):
    """Feed a sequence of {frontend: req_tot} dicts to _delta_and_buffer."""
    for totals in totals_sequence:
        agg._delta_and_buffer(totals)


def test_delta_buffers_first_sample_as_zeros():
    agg = LiveHostsAggregator(CFG)
    _drive(agg, [{"foo.com": 100, "bar.com": 50}])
    assert len(agg._buckets) == 1
    assert agg._buckets[0] == {"foo.com": 0, "bar.com": 0}


def test_delta_computes_increment():
    agg = LiveHostsAggregator(CFG)
    _drive(agg, [
        {"foo.com": 100},   # init
        {"foo.com": 142},   # +42
        {"foo.com": 150},   # +8
    ])
    assert agg._buckets[-1] == {"foo.com": 8}
    assert agg._buckets[-2] == {"foo.com": 42}


def test_delta_handles_haproxy_restart_no_negatives():
    agg = LiveHostsAggregator(CFG)
    _drive(agg, [
        {"foo.com": 1000},
        {"foo.com": 1050},   # +50
        {"foo.com": 12},     # counter reset -> treat as fresh
    ])
    # After reset the bucket value should be 0 (fresh baseline), never -1038.
    assert agg._buckets[-1].get("foo.com", 0) == 0


def test_ring_buffer_caps_at_60():
    agg = LiveHostsAggregator(CFG)
    for i in range(65):
        agg._delta_and_buffer({"foo.com": i * 10})
    assert len(agg._buckets) == 60


def test_aggregate_sums_buckets_top_n():
    agg = LiveHostsAggregator(dict(CFG, top_n=2))
    _drive(agg, [
        {"a.com": 0, "b.com": 0, "c.com": 0},      # baseline
        {"a.com": 30, "b.com": 10, "c.com": 5},    # deltas 30/10/5
        {"a.com": 40, "b.com": 25, "c.com": 6},    # deltas 10/15/1
    ])
    entries = agg._aggregate()
    hosts = [e["host"] for e in entries]
    assert hosts == ["a.com", "b.com"]
    counts = {e["host"]: e["count"] for e in entries}
    assert counts["a.com"] == 40
    assert counts["b.com"] == 25


def test_frontend_filter_strips_internal_names():
    agg = LiveHostsAggregator(CFG)
    raw = {
        "foo.com": 10,
        "_stats": 999,         # leading underscore -> drop
        "stats-https": 5,       # no dot -> drop
        "secubox.in": 50,
    }
    kept = agg._filter_frontends(raw)
    assert "foo.com" in kept
    assert "secubox.in" in kept
    assert "_stats" not in kept
    assert "stats-https" not in kept


def test_parse_show_stat_csv_extracts_frontends():
    csv = (
        "# pxname,svname,qcur,scur,smax,slim,stot,req_tot,extra\n"
        "stats-https,FRONTEND,0,0,0,0,0,5,\n"
        "secubox.in,FRONTEND,0,1,1,0,42,142,\n"
        "secubox.in,backend-a,0,0,0,0,0,0,\n"
        "apt.secubox.in,FRONTEND,0,0,0,0,0,9,\n"
    )
    out = LiveHostsAggregator._parse_show_stat(csv)
    assert out == {"stats-https": 5, "secubox.in": 142, "apt.secubox.in": 9}


def test_parse_show_stat_empty_or_malformed_returns_empty():
    assert LiveHostsAggregator._parse_show_stat("") == {}
    assert LiveHostsAggregator._parse_show_stat("garbage\n") == {}


def test_refresh_missing_socket_returns_disabled(tmp_path):
    agg = LiveHostsAggregator(dict(CFG, haproxy_socket=str(tmp_path / "missing.sock")))
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False
    assert out["entries"] == []
