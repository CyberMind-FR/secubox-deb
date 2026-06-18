# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for ad_ghost per-visitor accumulation on the block path (#659)."""
import time
import types

import pytest

from mitmproxy_addons import ad_ghost


def _flow(host, path="/", peer="10.99.1.5"):
    req = types.SimpleNamespace(
        pretty_host=host,
        path=path,
        headers=types.SimpleNamespace(get=lambda k, d="": d),
    )
    return types.SimpleNamespace(
        request=req,
        client_conn=types.SimpleNamespace(peername=(peer, 0)),
        response=None,
    )


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path):
    ad_ghost._ctx.clear()
    ad_ghost._cand.clear()
    ad_ghost._cli.clear()
    ad_ghost._allow = set()
    ad_ghost._allow_mtime = 0.0
    monkeypatch.setattr(ad_ghost, "_ALLOW_PATH", str(tmp_path / "ad-allowlist.txt"))
    monkeypatch.setattr(ad_ghost, "get_filters", lambda force=False: {
        "ad_ghost": 1, "ad_ghost_block": 1, "ad_learn": 1, "autolearn": 1,
        "ad_ghost_categories": {},
    })
    monkeypatch.setattr(ad_ghost, "mac_hash_of", lambda ip: "MH_FIXED")
    # Freeze the 5s flush gate so _flush() early-returns and never drains/clears
    # the hot-path dicts before we assert on them.
    monkeypatch.setattr(ad_ghost, "_last_flush", time.time())
    yield
    ad_ghost._ctx.clear()
    ad_ghost._cand.clear()
    ad_ghost._cli.clear()
    # These tests issue 204 blocks → reset the cumulative counter so we don't
    # pollute any later-collected test that asserts on _counts.
    ad_ghost._counts["blocked_requests"] = 0


def test_blocked_ad_recorded_per_visitor():
    flow = _flow("ad.doubleclick.net", path="/gampad/ads")
    ad_ghost.AdGhost().requestheaders(flow)
    assert flow.response is not None and flow.response.status_code == 204
    ck = ("MH_FIXED", "ad.doubleclick.net")
    assert ck in ad_ghost._cli
    assert ad_ghost._cli[ck][0] == 1
    assert ad_ghost._cli[ck][1] == ad_ghost._EST_BYTES_PER_REQ


def test_visitor_accumulates_across_requests():
    g = ad_ghost.AdGhost()
    g.requestheaders(_flow("ad.doubleclick.net", path="/a"))
    g.requestheaders(_flow("ad.doubleclick.net", path="/b"))
    assert ad_ghost._cli[("MH_FIXED", "ad.doubleclick.net")][0] == 2


def test_no_visitor_record_when_mac_hash_unavailable(monkeypatch):
    monkeypatch.setattr(ad_ghost, "mac_hash_of", lambda ip: None)
    ad_ghost.AdGhost().requestheaders(_flow("ad.doubleclick.net", path="/x"))
    assert ad_ghost._cli == {}


def test_non_ad_host_not_recorded_per_visitor():
    # not an ad host, not learned → no block, no per-visitor record
    ad_ghost.AdGhost().requestheaders(_flow("static.cnn.com", path="/img.png"))
    assert ad_ghost._cli == {}
