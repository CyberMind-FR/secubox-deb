# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2808 — routes /remote/* de l'App Store : gardes, transport vers la boite OpenPGP avec le jeton de l'admin, installation par le controleur."""
import importlib
import json
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(PKG.parents[1] / "common"))
from fastapi.testclient import TestClient  # noqa: E402

GK3 = "did:plc:" + "a" * 32


@pytest.fixture()
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSTORE_REMOTE_STATE", str(tmp_path / "remote.json"))
    import api.main as m
    importlib.reload(m)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    m.app.dependency_overrides[m.require_lecture] = lambda: {"sub": "admin"}
    m._bt = {"msgs": {}, "envois": []}

    def faux_openpgp(methode, chemin, token, corps=None):
        m._bt["jetons"] = m._bt.get("jetons", []) + [token]
        if (methode, chemin) == ("GET", "/boite"):
            return 200, {"messages": [{"id": i, "de": x["de"], "boxname": x["boxname"], "emis": 1} for i, x in m._bt["msgs"].items()]}
        if methode == "GET" and chemin.startswith("/boite/"):
            return 200, m._bt["msgs"][chemin.rsplit("/", 1)[1]]
        if (methode, chemin) == ("POST", "/envoyer"):
            m._bt["envois"].append(corps)
            return 200, {"ok": True, "a": GK3, "boxname": "gk3"}
        return 404, {}
    monkeypatch.setattr(m, "_openpgp", faux_openpgp)
    monkeypatch.setattr(m, "load_catalog", lambda: [{"name": "secubox-radio"}, {"name": "secubox-dns"}])
    return m, TestClient(m.app)


def depose(m, ident, objet, contenu, de=GK3):
    m._bt["msgs"][ident] = {"id": ident, "de": de, "boxname": "gk3", "emis": 1, "objet": objet, "contenu": contenu}


def test_demander_envoie_dans_la_boite_avec_le_jeton_de_l_admin(api):
    m, c = api
    r = c.post("/remote/demander", json={"pair": "gk3", "paquet": "secubox-radio"}, headers={"Authorization": "Bearer JETON"})
    assert r.status_code == 200 and r.json()["boxname"] == "gk3"
    env = m._bt["envois"][0]
    assert env["pair"] == "gk3" and env["objet"] == "appstore.install" and json.loads(env["contenu"])["paquet"] == "secubox-radio"
    assert "JETON" in m._bt["jetons"]


def test_demander_refuse_un_paquet_hors_catalogue(api):
    m, c = api
    r = c.post("/remote/demander", json={"pair": "gk3", "paquet": "secubox-inconnu"})
    assert r.status_code == 404 and m._bt["envois"] == []
    assert c.post("/remote/demander", json={"pair": "gk3", "paquet": "x;reboot"}).status_code in (400, 422)


def test_une_boite_injoignable_est_dite(api, monkeypatch):
    m, c = api
    monkeypatch.setattr(m, "_openpgp", lambda *a, **k: (0, {}))
    r = c.post("/remote/demander", json={"pair": "gk3", "paquet": "secubox-radio"})
    assert r.status_code == 502 and "OpenPGP" in r.json()["detail"]
    r = c.get("/remote/demandes")
    assert r.status_code == 200 and r.json()["boite"] == "indisponible"


def test_lister_range_les_demandes_recues(api):
    m, c = api
    depose(m, "m1", "appstore.install", json.dumps({"v": 1, "id": "e" * 32, "paquet": "secubox-radio"}))
    j = c.get("/remote/demandes").json()
    assert j["boite"] == "ok" and j["recues"][0]["paquet"] == "secubox-radio" and j["recues"][0]["etat"] == "en_attente"


def test_accepter_sans_retaper_le_nom_est_refuse(api, monkeypatch):
    m, c = api
    depose(m, "m1", "appstore.install", json.dumps({"v": 1, "id": "e" * 32, "paquet": "secubox-radio"}))
    c.get("/remote/demandes")
    monkeypatch.setattr(m, "_appstorectl", lambda *a, **k: pytest.fail("aucune installation"))
    r = c.post("/remote/demandes/m1/accepter")
    assert r.status_code == 428 and "secubox-radio" in r.json()["detail"]


def test_accepter_installe_par_le_controleur_et_repond(api, monkeypatch):
    m, c = api
    depose(m, "m1", "appstore.install", json.dumps({"v": 1, "id": "e" * 32, "paquet": "secubox-radio"}))
    c.get("/remote/demandes")
    appels = []
    monkeypatch.setattr(m, "_appstorectl", lambda args, input_text=None: appels.append(args) or (0, "installé", ""))
    r = c.post("/remote/demandes/m1/accepter?confirmer=secubox-radio", headers={"Authorization": "Bearer T"})
    assert r.status_code == 200 and r.json()["etat"] == "installee" and appels == [["install", "secubox-radio"]]
    rep = m._bt["envois"][-1]
    assert rep["pair"] == GK3 and rep["objet"] == "appstore.install.reponse" and json.loads(rep["contenu"])["statut"] == "installee"


def test_le_refus_du_controleur_est_rapporte(api, monkeypatch):
    m, c = api
    depose(m, "m1", "appstore.install", json.dumps({"v": 1, "id": "e" * 32, "paquet": "secubox-radio"}))
    c.get("/remote/demandes")
    monkeypatch.setattr(m, "_appstorectl", lambda *a, **k: (4, "", "paquet absent des dépôts"))
    r = c.post("/remote/demandes/m1/accepter?confirmer=secubox-radio")
    assert r.status_code == 200 and r.json()["etat"] == "echec" and "absent" in r.json()["message"]


def test_un_paquet_retire_du_catalogue_n_est_pas_installe(api, monkeypatch):
    m, c = api
    depose(m, "m1", "appstore.install", json.dumps({"v": 1, "id": "e" * 32, "paquet": "secubox-radio"}))
    c.get("/remote/demandes")
    monkeypatch.setattr(m, "load_catalog", lambda: [{"name": "secubox-dns"}])
    monkeypatch.setattr(m, "_appstorectl", lambda *a, **k: pytest.fail("hors catalogue : aucune installation"))
    r = c.post("/remote/demandes/m1/accepter?confirmer=secubox-radio")
    assert r.status_code == 200 and r.json()["etat"] == "echec" and "catalogue" in r.json()["message"]


def test_refuser(api):
    m, c = api
    depose(m, "m1", "appstore.install", json.dumps({"v": 1, "id": "e" * 32, "paquet": "secubox-radio"}))
    c.get("/remote/demandes")
    r = c.post("/remote/demandes/m1/refuser")
    assert r.status_code == 200 and r.json()["etat"] == "refusee"


def test_les_routes_d_ecriture_sont_gardees_par_le_jeton():
    src = (PKG / "api" / "main.py").read_text()
    for route in ('"/remote/demander"', '"/remote/demandes/{ident}/accepter"', '"/remote/demandes/{ident}/refuser"', '"/remote/demandes"'):
        ligne = next(l for l in src.splitlines() if route in l and "@app." in l)
        assert "require_jwt" in ligne, route
