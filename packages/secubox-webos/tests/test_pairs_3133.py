# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — GET /public/pairs, services des autres box (#3133)."""
import json

import pytest
from fastapi.testclient import TestClient

import api.main as m
from api import pairs


def _cache(tmp_path, contenu):
    f = tmp_path / "services-pairs.json"
    f.write_text(contenu if isinstance(contenu, str) else json.dumps(contenu))
    return f


def _doc(services):
    return {"version": 1, "genere": "2026-10-24T10:00:00Z",
            "pairs": [{"did": "did:sbx:a", "boxname": "alpha", "domaine": "alpha.exemple.test",
                       "mesh_ip": "10.8.0.2", "services": services}]}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(pairs, "CACHE", tmp_path / "services-pairs.json")
    m.app.dependency_overrides[m.require_lecture] = lambda: {"sub": "t"}
    yield TestClient(m.app)
    m.app.dependency_overrides.clear()


def test_cache_valide(client, tmp_path):
    _cache(tmp_path, _doc([{"nom": "blog", "endpoint": "https://blog.alpha.exemple.test",
                            "description": "Un blog"}]))
    j = client.get("/public/pairs").json()
    assert j["disponible"] is True and j["genere"] == "2026-10-24T10:00:00Z"
    assert j["pairs"][0]["services"][0]["nom"] == "blog"


def test_absent(client):
    r = client.get("/public/pairs")
    assert r.status_code == 200
    assert r.json() == {"pairs": [], "genere": None, "disponible": False}


def test_corrompu(client, tmp_path):
    _cache(tmp_path, "{pas du json")
    r = client.get("/public/pairs")
    assert r.status_code == 200 and r.json()["disponible"] is False


def test_mauvaise_version(client, tmp_path):
    d = _doc([])
    d["version"] = 2
    _cache(tmp_path, d)
    assert client.get("/public/pairs").json()["disponible"] is False


@pytest.mark.parametrize("ep", ["javascript:alert(1)", "http://x.exemple.test",
                                "https://" + "a" * 250, 42, None])
def test_endpoint_ecarte(client, tmp_path, ep):
    _cache(tmp_path, _doc([{"nom": "mauvais", "endpoint": ep, "description": ""},
                           {"nom": "bon", "endpoint": "https://ok.exemple.test", "description": ""}]))
    svcs = client.get("/public/pairs").json()["pairs"][0]["services"]
    assert [s["nom"] for s in svcs] == ["bon"]


def test_bornes(client, tmp_path):
    svcs = [{"nom": f"s{i}", "endpoint": "https://x.exemple.test", "description": "d"} for i in range(100)]
    d = _doc(svcs)
    d["pairs"] = d["pairs"] * 40
    _cache(tmp_path, d)
    j = client.get("/public/pairs").json()
    assert len(j["pairs"]) == 32 and len(j["pairs"][0]["services"]) == 64


def test_nom_trop_long_ou_non_str(client, tmp_path):
    _cache(tmp_path, _doc([{"nom": "n" * 64, "endpoint": "https://x.exemple.test", "description": ""},
                           {"nom": 5, "endpoint": "https://x.exemple.test", "description": ""}]))
    assert client.get("/public/pairs").json()["pairs"][0]["services"] == []


def test_sans_session(tmp_path, monkeypatch):
    import secubox_core.auth as auth
    monkeypatch.setattr(auth, "mode_tableau_de_bord_actif", lambda: False)
    monkeypatch.setattr(pairs, "CACHE", tmp_path / "x.json")
    m.app.dependency_overrides.clear()
    r = TestClient(m.app).get("/public/pairs")
    assert r.status_code in (401, 403)
