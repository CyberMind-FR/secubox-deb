# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API /moi du Coffre (P5, #1367) : la personne vient de la SESSION, la
serrure de la requête, et un en-tête n'y change rien."""
import base64
import os

import pytest
from fastapi.testclient import TestClient

from api import main as m
from coffre.coffre import Coffre
from coffre.journal import Journal
from secubox_core import capacites
from secubox_core.auth import require_personne

PHRASE = "une phrase assez longue pour le coffre"
ALICE = "0b6e3c3a-7d0f-4c1e-9a55-3f2a1b8c9d10"
BOB = "4f1d2e3c-1a2b-4c3d-8e9f-0a1b2c3d4e5f"
A = {"secret": "la phrase personnelle d'alice", "genre": "phrase"}
PERSONNES = {"alice": ALICE, "bob": BOB}


def b64u(o):
    return base64.urlsafe_b64encode(o).decode().rstrip("=")


@pytest.fixture
def moi(monkeypatch, tmp_path):
    c = Coffre(tmp_path / "c", Journal(tmp_path / "j"), argon2={"t": 1, "m": 1024, "p": 1})
    c.initialiser(PHRASE)
    monkeypatch.setattr(m, "COFFRE", c)
    monkeypatch.setattr(m, "_echecs", __import__("collections").defaultdict(__import__("collections").deque))
    qui = {"sub": "alice"}
    monkeypatch.setattr(capacites, "personne_du_porteur",
                        lambda p: {"user_uuid": PERSONNES[p["sub"]], "pseudo": p["sub"]}
                        if p.get("sub") in PERSONNES else None)
    m.public.dependency_overrides[require_personne] = lambda: dict(qui)
    yield TestClient(m.public), qui
    m.public.dependency_overrides.clear()


def test_cycle_de_la_personne(moi):
    cl, _ = moi
    assert cl.get("/moi").json()["serrures"] == []
    assert cl.post("/moi/initialiser", json={"phrase": A["secret"]}).status_code == 200
    assert cl.post("/moi/secrets", json={"ouverture": A, "nom": "gpg", "valeur": "clé"}).json()["version"] == 1
    assert cl.post("/moi/secrets/lister", json={"ouverture": A}).json()["secrets"][0]["nom"] == "gpg"
    assert cl.post("/moi/secrets/gpg/lire", json={"ouverture": A}).json()["valeur"] == "clé"
    assert cl.post("/moi/secrets/gpg/retirer", json={"ouverture": A}).json()["retire"] is True
    assert cl.get("/moi").json()["secrets"] == 0


def test_la_personne_vient_de_la_session_pas_d_un_en_tete(moi):
    cl, qui = moi
    cl.post("/moi/initialiser", json={"phrase": A["secret"]})
    cl.post("/moi/secrets", json={"ouverture": A, "nom": "x", "valeur": "a alice"})
    qui["sub"] = "bob"
    r = cl.post("/moi/secrets/x/lire", json={"ouverture": A},
                headers={"X-SecuBox-Personne": ALICE, "X-Sbx-User-Id": ALICE})
    assert r.status_code == 403                    # Bob, même avec la phrase d'Alice
    qui["sub"] = "inconnu"
    assert cl.get("/moi").status_code == 403       # aucune personne derrière la session


def test_serrure_refusee_cinq_fois_puis_429(moi):
    cl, _ = moi
    cl.post("/moi/initialiser", json={"phrase": A["secret"]})
    faux = {"ouverture": {"secret": "pas la bonne phrase", "genre": "phrase"}}
    codes = [cl.post("/moi/secrets/lister", json=faux).status_code for _ in range(6)]
    assert codes == [403] * 5 + [429]
    assert cl.post("/moi/secrets/lister", json={"ouverture": A}).status_code == 429


def test_cle_d_appareil_personnelle(moi):
    cl, _ = moi
    cl.post("/moi/initialiser", json={"phrase": A["secret"]})
    sel = cl.post("/moi/serrures/appareil/preparer").json()["sel"]
    prf = b64u(os.urandom(32))
    r = cl.post("/moi/serrures/appareil", json={"ouverture": A, "cred_id": "D" * 43, "sel": sel, "prf": prf,
                                               "libelle": "téléphone"})
    assert r.status_code == 200
    par_cle = {"secret": prf, "genre": "appareil", "cred_id": "D" * 43}
    cl.post("/moi/secrets", json={"ouverture": par_cle, "nom": "x", "valeur": "v"})
    assert cl.post("/moi/secrets/x/lire", json={"ouverture": A}).json()["valeur"] == "v"
    appareil = next(s for s in cl.get("/moi").json()["serrures"] if s["genre"] == "appareil")
    assert appareil["cred_id"] == "D" * 43 and appareil["sel"] == sel


def test_scelle_423_et_admin_sans_acces(moi):
    cl, _ = moi
    cl.post("/moi/initialiser", json={"phrase": A["secret"]})
    m.COFFRE.sceller()
    assert cl.post("/moi/secrets/lister", json={"ouverture": A}).status_code == 423
