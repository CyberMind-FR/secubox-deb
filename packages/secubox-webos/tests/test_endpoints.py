# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — endpoints /public/services (minimal) et /services (JWT)."""
from fastapi.testclient import TestClient
import api.main as m
from api.main import app, require_jwt


def _seed():
    m._flags = {"enabled": True, "registry_enabled": True}
    m._cache["services"] = [
        m.Service(id="waf", name="WAF", category="wall", icon="🔥",
                  urls={"path": "/waf/", "lan": "https://waf.gk2.secubox.in", "wan": "https://waf.gk2.secubox.in"},
                  routing={"mode": "wan"}, health={"state": "online", "latency_ms": 5.0},
                  auth={}).model_dump()
    ]
    m._cache["computed_at"] = 123.0


def test_public_is_minimal():
    _seed()
    c = TestClient(app)
    r = c.get("/public/services")
    assert r.status_code == 200
    svc = r.json()["services"][0]
    assert svc["id"] == "waf" and svc["health"]["state"] == "online"
    assert "urls" not in svc and "latency_ms" not in str(svc)   # pas de fuite


def test_detail_requires_jwt_and_is_full():
    _seed()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "gk2"}
    try:
        c = TestClient(app)
        svc = c.get("/services").json()["services"][0]
        assert svc["urls"]["wan"] == "https://waf.gk2.secubox.in"
        assert svc["health"]["latency_ms"] == 5.0
    finally:
        app.dependency_overrides.clear()


def test_detail_requires_jwt_401_without_token():
    _seed()
    c = TestClient(app)
    r = c.get("/services")
    assert r.status_code == 401


def test_flag_off_empty(monkeypatch):
    # _seed() enables flags first (see below); the flag-off patch must be
    # applied AFTER _seed() so it isn't clobbered by the seed's own reset.
    _seed()
    monkeypatch.setattr(m, "_flags", {"enabled": False, "registry_enabled": True})
    c = TestClient(app)
    assert c.get("/public/services").json()["services"] == []


def test_healthz_still_ok():
    c = TestClient(app)
    r = c.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
