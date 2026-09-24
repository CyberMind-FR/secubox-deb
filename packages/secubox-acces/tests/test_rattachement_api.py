# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Routes de rattachement (#1369) : compte SecuBox, sessions coupées, défaut."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

main = pytest.importorskip("api.main")
from fastapi.testclient import TestClient  # noqa: E402

from api.profileur import Profileur  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_acces import DID, admis  # noqa: E402

COMPTES = [
    {"handle": "gk2", "nom": "gk2", "role": "admin", "desactive": False},
    {"handle": "operator", "nom": "operator", "role": "operator", "desactive": False},
    {"handle": "ancien", "nom": "ancien", "role": "admin", "desactive": True},
]


@pytest.fixture
def banc(tmp_path, monkeypatch):
    prof = Profileur(tmp_path / "demandes.json")
    monkeypatch.setattr(main, "_profileur", prof)
    monkeypatch.setattr(main, "_comptes_secubox", lambda: [dict(c) for c in COMPTES])
    evts = []
    monkeypatch.setattr(main, "_emit_session_event", lambda e, u, d: evts.append((e, u, d)))
    monkeypatch.setattr(main.appareils, "inscris", lambda *a, **k: None)
    monkeypatch.setattr(main.appareils, "revoque", lambda *a, **k: True)

    async def _pas_de_bbs(req, noms):
        return {}
    monkeypatch.setattr(main, "_etat_bbs", _pas_de_bbs)
    main.app.dependency_overrides[main.require_admin] = lambda: {"sub": "gk2"}
    yield TestClient(main.app), prof, evts
    main.app.dependency_overrides.clear()


def test_rattacher_a_gk2_donne_le_profil_admin_et_coupe_les_sessions(banc):
    client, prof, evts = banc
    admis(prof)
    prof.note_session(DID, "jti-sbx")
    r = client.post("/profils/rattacher", json={"did": DID, "compte": "gk2"})
    assert r.status_code == 200, r.text
    assert r.json()["profil"] == "admin" and r.json()["sessions_coupees"] == 1
    e, u, d = evts[-1]
    assert e == "sessions_coupees" and u.startswith("sbx-") and d["jtis"] == ["jti-sbx"]


def test_un_compte_operateur_donne_le_profil_user(banc):
    client, prof, _ = banc
    admis(prof)
    r = client.post("/profils/rattacher", json={"did": DID, "compte": "operator"})
    assert r.json()["profil"] == "user"


def test_on_ne_rattache_pas_a_un_compte_ferme_ou_inconnu(banc):
    client, prof, _ = banc
    admis(prof)
    for nom in ("ancien", "personne"):
        r = client.post("/profils/rattacher", json={"did": DID, "compte": nom})
        assert r.status_code == 400, nom
    assert prof.demande_de(DID).compte is None


def test_detacher_repart_de_guest(banc):
    client, prof, _ = banc
    admis(prof)
    client.post("/profils/rattacher", json={"did": DID, "compte": "gk2"})
    r = client.post("/profils/rattacher", json={"did": DID, "compte": ""})
    assert r.json()["profil"] == "guest" and prof.demande_de(DID).compte is None


def test_revoquer_un_appareil_rattache_coupe_ses_sessions_au_nom_du_compte(banc):
    client, prof, evts = banc
    admis(prof)
    client.post("/profils/rattacher", json={"did": DID, "compte": "gk2"})
    prof.note_session(DID, "jti-gk2-iphone")
    r = client.post("/profils/revoquer", json={"did": DID})
    assert r.json()["sessions_coupees"] == 1
    assert evts[-1] == ("sessions_coupees", "gk2", {"jtis": ["jti-gk2-iphone"], "voie": "acces"})


def test_profils_propose_le_compte_du_noeud(banc, monkeypatch):
    client, prof, _ = banc
    admis(prof)
    import socket
    monkeypatch.setattr(socket, "gethostname", lambda: "gk2")
    j = client.get("/profils").json()
    assert j["compte_par_defaut"] == "gk2"
    assert [c["handle"] for c in j["comptes"]] == ["gk2", "operator", "ancien"]
    monkeypatch.setattr(socket, "gethostname", lambda: "autre")
    assert client.get("/profils").json()["compte_par_defaut"] == "gk2"   # premier admin actif
