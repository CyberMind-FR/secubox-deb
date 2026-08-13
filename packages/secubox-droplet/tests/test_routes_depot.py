# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Les routes de dépôt, de bout en bout (#1026)."""
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)

    from api import routes_depot as rd
    monkeypatch.setattr(rd, "_conf", lambda: {
        "depots_dir": str(tmp_path / "depots"),
        "taille_max": 4096,
        "fichiers_max": 3,
        "quota_octets_par_heure": 0,
        "quota_depots_par_heure": 0,
    })
    # L'alerte est remplacée : le test vérifie le DEPOT, pas le courrier.
    envois = []
    monkeypatch.setattr(rd._alerte, "envoie",
                        lambda d, **kw: (envois.append(d), {"ok": True, "detail": "ok"})[1])
    monkeypatch.setattr(rd, "_limiteur", None)

    from secubox_core.auth import require_jwt
    app = FastAPI()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    app.include_router(rd.router)
    c = TestClient(app)
    c.envois = envois
    c.racine = tmp_path / "depots"
    return c


def test_un_depot_simple(client):
    r = client.post("/depot", files={"fichiers": ("rapport.zip", b"PK\x03\x04hello")})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ok"] is True and d["taille"] == 9
    assert d["fichiers"][0]["nom"] == "rapport.zip"
    assert len(d["depot"]) > 20


def test_les_octets_sont_sur_le_disque_sous_un_nom_a_nous(client):
    r = client.post("/depot", files={"fichiers": ("../../evade.zip", b"abc")})
    dossier = client.racine / r.json()["depot"]
    # Le nom fourni ne designe RIEN sur le disque : le chemin vient de l'indice.
    assert (dossier / "00.bin").read_bytes() == b"abc"
    assert not (dossier / "evade.zip").exists()
    # Et le nom nettoye survit dans le manifeste, pour l'humain.
    m = json.loads((dossier / "manifeste.json").read_text())
    assert m["fichiers"][0]["nom"] == "evade.zip"
    assert m["fichiers"][0]["sur_disque"] == "00.bin"


def test_deux_fichiers_homonymes_ne_s_ecrasent_pas(client):
    r = client.post("/depot", files=[
        ("fichiers", ("a.txt", b"premier")),
        ("fichiers", ("a.txt", b"second")),
    ])
    d = r.json()
    assert d["taille"] == 13
    dossier = client.racine / d["depot"]
    assert (dossier / "00.bin").read_bytes() == b"premier"
    assert (dossier / "01.bin").read_bytes() == b"second"


def test_le_manifeste_survit_a_l_alerte(client):
    # Le courrier peut se perdre, la boite peut etre videe ; le dossier doit se
    # suffire a lui-meme, sans quoi on garde des 00.bin anonymes.
    r = client.post("/depot", data={"mot": "pour Gérald"},
                    files={"fichiers": ("x.bin", b"0" * 100)})
    m = json.loads((client.racine / r.json()["depot"] / "manifeste.json").read_text())
    assert m["mot"] == "pour Gérald"
    assert m["fichiers"][0]["taille"] == 100
    assert len(m["fichiers"][0]["sha256"]) == 64


def test_au_dela_du_plafond_refuse_et_rien_ne_reste(client):
    r = client.post("/depot", files={"fichiers": ("gros.bin", b"z" * 5000)})
    assert r.status_code == 413
    assert list(client.racine.iterdir()) == []


def test_trop_de_fichiers_refuse(client):
    r = client.post("/depot", files=[("fichiers", (f"{i}.txt", b"x")) for i in range(4)])
    assert r.status_code == 400


def test_l_inventaire_rend_les_manifestes_jamais_les_octets(client):
    client.post("/depot", files={"fichiers": ("a.zip", b"secret")})
    d = client.get("/depots").json()
    assert d["total"] == 1
    entree = d["depots"][0]
    assert entree["fichiers"][0]["nom"] == "a.zip"
    # Le contenu n'apparait nulle part — aucune route ne le sert.
    assert "secret" not in json.dumps(d)


def test_un_manifeste_illisible_est_signale_pas_saute(client):
    r = client.post("/depot", files={"fichiers": ("a.zip", b"x")})
    (client.racine / r.json()["depot"] / "manifeste.json").write_text("{cassé")
    d = client.get("/depots").json()
    assert d["total"] == 1 and "erreur" in d["depots"][0]


def test_les_reglages_sont_annonces_avant_l_envoi(client):
    # Decouvrir un plafond en se le prenant apres dix minutes de televersement
    # est la pire facon de l'apprendre.
    r = client.get("/depot/reglages").json()
    assert r["taille_max"] == 4096 and r["fichiers_max"] == 3


def test_la_sante_repose_sur_une_ecriture(client):
    assert client.get("/depot/sante").json()["status"] == "ok"
