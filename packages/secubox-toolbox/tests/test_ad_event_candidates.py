# tests/test_ad_event_candidates.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#662 — /__toolbox/ad-event accepts a "candidates" list (the Go engine's
auto-learn feed) → store.record_ad_candidates(). Never 500s the engine."""
import asyncio
import json

from secubox_toolbox import api, store


class _FakeRequest:
    """Minimal Request stand-in: headers + an async json() body."""

    def __init__(self, body: dict, content_length=None):
        self._body = body
        cl = content_length
        if cl is None:
            cl = len(json.dumps(body).encode())
        self.headers = {"content-length": str(cl)}

    async def json(self):
        return self._body


def test_candidates_ingested(monkeypatch):
    captured = {}
    monkeypatch.setattr(store, "record_ad_candidates", lambda rows: captured.setdefault("cand", list(rows)))
    monkeypatch.setattr(store, "record_ad_blocks", lambda rows: None)
    monkeypatch.setattr(store, "record_ad_client_blocks", lambda rows: None)

    body = {
        "blocks": [],
        "clients": [],
        "candidates": [
            {"host": "metrics.acotedemoi.com", "site": "lemonde.fr", "hits": 3},
            {"host": "ads.foo.io", "site": "news.example", "hits": 1},
            {"site": "no-host.example", "hits": 9},        # missing host → skipped
            {"host": "", "site": "x", "hits": 2},          # empty host → skipped
        ],
    }
    resp = asyncio.run(api.toolbox_ad_event(_FakeRequest(body)))
    assert resp.status_code == 204
    rows = captured.get("cand")
    assert rows == [
        ("metrics.acotedemoi.com", "lemonde.fr", 3),
        ("ads.foo.io", "news.example", 1),
    ]


def test_candidates_absent_is_noop(monkeypatch):
    called = {"cand": False}
    monkeypatch.setattr(store, "record_ad_candidates", lambda rows: called.__setitem__("cand", True))
    monkeypatch.setattr(store, "record_ad_blocks", lambda rows: None)
    monkeypatch.setattr(store, "record_ad_client_blocks", lambda rows: None)

    resp = asyncio.run(api.toolbox_ad_event(_FakeRequest({"blocks": [], "clients": []})))
    assert resp.status_code == 204
    assert called["cand"] is False  # no candidates key → record_ad_candidates not called


def test_candidates_bad_payload_never_500s(monkeypatch):
    monkeypatch.setattr(store, "record_ad_candidates", lambda rows: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(store, "record_ad_blocks", lambda rows: None)
    monkeypatch.setattr(store, "record_ad_client_blocks", lambda rows: None)

    body = {"candidates": [{"host": "x.io", "site": "s", "hits": 1}]}
    resp = asyncio.run(api.toolbox_ad_event(_FakeRequest(body)))
    assert resp.status_code == 204  # store raised, but the endpoint swallows it
