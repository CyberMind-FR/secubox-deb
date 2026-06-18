# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for ad_ghost contextual recording + candidates + allowlist (#656)."""
import types

import pytest

from mitmproxy_addons import ad_ghost


def _flow(host, path="/", referer="", peer="10.99.1.2"):
    headers = {}
    if referer:
        headers["referer"] = referer
    req = types.SimpleNamespace(
        pretty_host=host,
        path=path,
        headers=types.SimpleNamespace(get=lambda k, d="": headers.get(k.lower(), d)),
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
    ad_ghost._allow = set()
    ad_ghost._allow_mtime = 0.0
    monkeypatch.setattr(ad_ghost, "_ALLOW_PATH", str(tmp_path / "ad-allowlist.txt"))
    monkeypatch.setattr(ad_ghost, "get_filters", lambda force=False: {
        "ad_ghost": 1, "ad_ghost_block": 1, "ad_learn": 1, "autolearn": 1,
        "ad_ghost_categories": {},
    })
    yield
    ad_ghost._ctx.clear()
    ad_ghost._cand.clear()


def test_allowlist_host_not_blocked(monkeypatch, tmp_path):
    # doubleclick.net matches _AD_HOST but is allowlisted → must NOT be blocked.
    p = tmp_path / "ad-allowlist.txt"
    p.write_text("doubleclick.net\n")
    monkeypatch.setattr(ad_ghost, "_ALLOW_PATH", str(p))
    ad_ghost._allow = set()
    ad_ghost._allow_mtime = 0.0
    flow = _flow("ad.doubleclick.net", path="/gampad/ads")
    AdGhost = ad_ghost.AdGhost()
    AdGhost.requestheaders(flow)
    assert flow.response is None  # allowlist wins
    assert ad_ghost._counts["blocked_requests"] == 0


def test_third_party_ad_path_captured_as_candidate():
    flow = _flow("tracker.example.io", path="/pixel/collect",
                 referer="https://www.cnn.com/news")
    ad_ghost.AdGhost().requestheaders(flow)
    # not a known/learned ad host → not blocked, but captured as candidate
    assert flow.response is None
    assert ("tracker.example.io", "cnn.com") in ad_ghost._cand
    assert ad_ghost._cand[("tracker.example.io", "cnn.com")] == 1


def test_first_party_not_captured():
    # same registrable as the site → first-party, NOT a candidate
    flow = _flow("static.cnn.com", path="/ads/banner",
                 referer="https://www.cnn.com/news")
    ad_ghost.AdGhost().requestheaders(flow)
    assert ad_ghost._cand == {}


def test_site_of_extracts_registrable():
    flow = _flow("x.io", path="/", referer="https://sub.bbc.co.uk/article")
    assert ad_ghost._site_of(flow) == "bbc.co.uk"
    flow2 = _flow("x.io", path="/", referer="https://www.cnn.com/news")
    assert ad_ghost._site_of(flow2) == "cnn.com"
