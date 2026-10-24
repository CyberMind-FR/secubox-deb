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


DID = "did:plc:" + "a" * 32


def _cache(tmp_path, contenu):
    f = tmp_path / "services-pairs.json"
    f.write_text(contenu if isinstance(contenu, str) else json.dumps(contenu))
    return f


def _doc(services):
    return {"version": 1, "genere": "2026-10-24T10:00:00Z",
            "pairs": [{"did": DID, "boxname": "alpha", "domaine": "alpha.exemple.test",
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
    assert r.status_code == 401


def test_json_tres_imbrique(client, tmp_path):
    _cache(tmp_path, "[" * 100000)
    r = client.get("/public/pairs")
    assert r.status_code == 200 and r.json()["disponible"] is False


def test_fichier_trop_gros(client, tmp_path):
    _cache(tmp_path, " " * (pairs.MAX_OCTETS + 1))
    assert client.get("/public/pairs").json() == {"pairs": [], "genere": None, "disponible": False}


@pytest.mark.parametrize("doc", [{"version": 1, "pairs": {}}, {"version": 1, "pairs": "x"},
                                 {"version": True, "pairs": []}, {"version": 2, "pairs": []},
                                 {"pairs": []}, [1, 2]])
def test_structure_invalide(client, tmp_path, doc):
    _cache(tmp_path, doc)
    assert client.get("/public/pairs").json()["disponible"] is False


def test_pair_pas_un_dict_et_services_pas_une_liste(client, tmp_path):
    d = _doc([])
    d["pairs"] = [5, "x", None, {"did": DID, "boxname": "b", "services": "nope"}]
    _cache(tmp_path, d)
    j = client.get("/public/pairs").json()
    assert j["disponible"] is True and len(j["pairs"]) == 1 and j["pairs"][0]["services"] == []


@pytest.mark.parametrize("ep", [
    "https://admin@phish.exemple.test", "https://a.exemple.test\\x", "https://a.exemple.test/\"x",
    "https://a.exemple.test/<x>", "https://a.exemple.test/a b", "https://a.exemple.test/a\nb",
    "https://a.exemple.test/a\u202eb", "https://a.exemple.test:8443/", "https://a.exemple.test/?x=1",
    "https://a.exemple.test/#f", "https://A.exemple.test", "https://localhost", "https://",
    "https://a.exemple.test\n"])
def test_endpoint_hostile(client, tmp_path, ep):
    _cache(tmp_path, _doc([{"nom": "x", "endpoint": ep, "description": ""}]))
    assert client.get("/public/pairs").json()["pairs"][0]["services"] == []


def test_endpoint_avec_chemin_accepte(client, tmp_path):
    ep = "https://blog.alpha.exemple.test/a/b-c_d.e~f%20"
    _cache(tmp_path, _doc([{"nom": "x", "endpoint": ep, "description": ""}]))
    assert client.get("/public/pairs").json()["pairs"][0]["services"][0]["endpoint"] == ep


@pytest.mark.parametrize("did", ["did:sbx:a", "did:plc:" + "A" * 32, "did:plc:" + "a" * 31,
                                 "did:plc:" + "a" * 32 + "\n", 5, None])
def test_did_invalide_ecarte_la_paire(client, tmp_path, did):
    d = _doc([{"nom": "x", "endpoint": "https://ok.exemple.test", "description": ""}])
    d["pairs"][0]["did"] = did
    _cache(tmp_path, d)
    assert client.get("/public/pairs").json()["pairs"] == []


def test_champs_texte_et_ip(client, tmp_path):
    d = _doc([{"nom": "bon\u200bnom", "endpoint": "https://ok.exemple.test", "description": "a\x07b"},
              {"nom": "ok", "endpoint": "https://ok.exemple.test", "description": "fine"}])
    d["pairs"][0]["mesh_ip"] = "999.1.1.1"
    d["pairs"][0]["boxname"] = "al\u202epha"
    _cache(tmp_path, d)
    p = client.get("/public/pairs").json()["pairs"][0]
    assert p["mesh_ip"] == "" and p["boxname"] == ""
    assert [s["nom"] for s in p["services"]] == ["ok"]
