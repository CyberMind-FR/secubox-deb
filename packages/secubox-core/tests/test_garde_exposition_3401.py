# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 : garde commune des chemins d'exposition (vhost, ACME, contournement WAF, Tor, reach)."""
import json
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from secubox_core import garde_exposition as G

PAQUETS = Path(__file__).resolve().parents[2]


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    a = FastAPI()

    @a.post("/x", dependencies=[Depends(G.exiger_mot_de_passe_change)])
    def x():
        return {"ok": True}
    a.users = tmp_path / "users.json"
    monkeypatch.setenv("SECUBOX_USERS_JSON", str(a.users))
    return a


def _users(f, mdp):
    f.write_text(json.dumps({"users": [{"username": "admin", "password_hash": PasswordHasher().hash(mdp)}]}))


def test_refus_409_si_defaut_actif_avec_un_vrai_users_json(app, tmp_path):
    _users(app.users, "secubox")
    r = TestClient(app).post("/x")
    assert r.status_code == 409 and "mot de passe par défaut" in r.json()["detail"]
    assert "exposition_refusee" in (tmp_path / "audit.log").read_text()


def test_refus_si_inconnu(app):
    app.users.write_text("{corrompu")
    assert TestClient(app).post("/x").status_code == 409


def test_permis_apres_changement(app):
    _users(app.users, "une phrase longue et choisie")
    assert TestClient(app).post("/x").status_code == 200


@pytest.mark.parametrize("fichier,route", [
    ("secubox-haproxy/api/main.py", '@router.post("/vhost"'),
    ("secubox-haproxy/api/main.py", '@router.post("/vhost/{name}/waf-bypass"'),
    ("secubox-haproxy/api/main.py", '@router.post("/certificates/acme"'),
    ("secubox-haproxy/composants/vhost/api/main.py", '@app.post("/vhost"'),
    ("secubox-haproxy/composants/vhost/api/main.py", '@app.post("/certificate/issue"'),
    ("secubox-tor/api/main.py", '@app.post("/hidden_service/add"'),
])
def test_chemins_d_exposition_gardes(fichier, route):
    src = (PAQUETS / fichier).read_text()
    i = src.index(route)
    assert "exiger_mot_de_passe_change" in src[i:i + 600], route
