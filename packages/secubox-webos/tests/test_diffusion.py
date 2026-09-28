# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Diffusion au parc : réservée aux personnes, URL en liste blanche (#1608)."""
from fastapi.testclient import TestClient

import api.main as m
from api.main import app
from secubox_core.auth import require_personne


def test_diffuser_sans_session_refuse():
    c = TestClient(app)
    assert c.post("/public/broadcast", json={"url": "/api/v1/ytsas/stream/x"}).status_code == 401
    assert c.post("/public/broadcast/like", json={"url": "/x"}).status_code == 401


def test_url_diffusable(monkeypatch):
    monkeypatch.setattr(m, "domaine_box", lambda: "gk2.secubox.in")
    assert m._url_diffusable("/api/v1/ytsas/stream/abc")
    assert m._url_diffusable("https://www.youtube.com/watch?v=x")
    assert m._url_diffusable("https://hall.gk2.secubox.in/sbxos/")
    for u in ("//exemple.org/x", "javascript:alert(1)", "http://www.youtube.com/",
              "https://exemple.org/", "https://gk2.secubox.in.exemple.org/",
              "https://u:p@hall.gk2.secubox.in/", "data:text/html,x", "/\\exemple.org"):
        assert not m._url_diffusable(u), u


def test_personne_diffuse_et_aime_une_fois(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "_BROADCAST_FILE", tmp_path / "b.json")
    monkeypatch.setattr(m, "_HIST_FILE", tmp_path / "h.json")
    monkeypatch.setattr(m, "_hist", [])
    monkeypatch.setattr(m, "_AIME", {})
    monkeypatch.setattr(m, "_DEBIT", {})
    app.dependency_overrides[require_personne] = lambda: {"sub": "alice"}
    try:
        c = TestClient(app)
        r = c.post("/public/broadcast", json={"url": "/api/v1/ytsas/stream/abc", "titre": "t"})
        assert r.status_code == 200 and r.json()["actif"] is True
        assert c.post("/public/broadcast", json={"url": "https://exemple.org/"}).status_code == 422
        assert c.post("/public/broadcast/like", json={"url": "/api/v1/ytsas/stream/abc"}).json()["likes"] == 1
        assert c.post("/public/broadcast/like", json={"url": "/api/v1/ytsas/stream/abc"}).json()["likes"] == 1
    finally:
        app.dependency_overrides.clear()


def test_cardlet_waf_sans_session_sans_adresse(monkeypatch):
    d = {"id": "waf", "recent": [{"ip": "203.0.113.9", "country": "FR", "categorie": "x", "action": "ban"}]}
    async def cache():
        return d
    monkeypatch.setattr(m, "_cardlet_waf_cache", cache)
    c = TestClient(app)
    r = c.get("/public/cardlets/waf").json()
    assert r["recent"] == [{"country": "FR", "categorie": "x", "action": "ban"}]
    monkeypatch.setattr(m, "_session_reconnue", lambda req: True)
    assert c.get("/public/cardlets/waf").json()["recent"][0]["ip"] == "203.0.113.9"
