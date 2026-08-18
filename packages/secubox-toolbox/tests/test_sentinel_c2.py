# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from fastapi.testclient import TestClient
from secubox_toolbox.app import app
from secubox_toolbox import sentinel_link as sl

client = TestClient(app)


def test_c2_route_active(monkeypatch):
    monkeypatch.setattr(sl, "fetch_c2", lambda: {
        "learned": [{"host": "x7f3q9zk2vw8plmn.example", "signals": ["dga", "rare"],
                     "interval_s": 300.0, "devices": 1}],
        "candidates": [],
    })
    r = client.get("/admin/sentinel/c2")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["learned"][0]["host"] == "x7f3q9zk2vw8plmn.example"


def test_c2_route_failsafe(monkeypatch):
    monkeypatch.setattr(sl, "fetch_c2", lambda: {})
    r = client.get("/admin/sentinel/c2")
    assert r.status_code == 200
    assert r.json() == {"active": False, "learned": [], "candidates": []}


def test_c2_allow_route(monkeypatch):
    called = {}

    def _fake_allow(host):
        called["host"] = host
        return True

    monkeypatch.setattr(sl, "c2_allow", _fake_allow)
    r = client.post("/admin/sentinel/c2/allow", data={"host": "fp.example"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert called["host"] == "fp.example"


def test_c2_route_normalizes_candidate_maps(monkeypatch):
    monkeypatch.setattr(sl, "fetch_c2", lambda: {
        "learned": [{"host": "l.example", "signals": ["dga"], "interval_s": 300.0, "devices": 2}],
        "candidates": [{"host": "c.example", "signals": {"dga": True, "rare": True},
                        "interval_s": 120.0, "windows": 2}],
    })
    r = client.get("/admin/sentinel/c2")
    body = r.json()
    assert body["candidates"][0]["signals"] == ["dga", "rare"]  # object → sorted list
    assert body["candidates"][0]["windows"] == 2
    assert body["learned"][0]["signals"] == ["dga"]  # list passthrough
