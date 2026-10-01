# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API du Coffre (#1367 P1) : la face publique n'est pas un oracle.

Publique (administrateurs, via l'agrégateur) : ouvrir, sceller, noms, poser,
retirer, journal — jamais une valeur ; hors LAN, un TOTP ; 5 échecs/h puis 429.
Racine (coffrectl) : initialiser, lire, serrures.
"""
import pytest
from fastapi.testclient import TestClient

from api import main as m
from coffre.coffre import Coffre
from coffre.journal import Journal
from secubox_core import second_facteur
from secubox_core.auth import require_jwt

PHRASE = "une phrase assez longue pour le coffre"
LAN = {"X-SecuBox-LAN": "1"}
# Le harnais de test arme le verdict LAN par défaut (#1256) : le WAN se dit.
WAN = {"X-SecuBox-LAN": "0"}


@pytest.fixture
def clients(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "COFFRE", Coffre(tmp_path / "c", Journal(tmp_path / "j"),
                                            argon2={"t": 1, "m": 1024, "p": 1}))
    monkeypatch.setattr(m, "_echecs", __import__("collections").defaultdict(__import__("collections").deque))
    monkeypatch.setattr(second_facteur, "otp_lan", lambda: "facultatif")
    m.public.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(m.public), TestClient(m.racine)
    m.public.dependency_overrides.clear()


def test_publique_exige_un_administrateur(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "COFFRE", Coffre(tmp_path / "c", Journal(tmp_path / "j")))
    c = TestClient(m.public)
    for meth, chemin in (("get", "/etat"), ("post", "/sceller"), ("get", "/secrets"), ("get", "/journal")):
        assert getattr(c, meth)(chemin).status_code in (401, 403), chemin
    assert c.post("/ouvrir", json={"secret": PHRASE}).status_code in (401, 403)
    assert c.get("/health").status_code == 200


def test_cycle_complet_et_aucune_valeur_cote_public(clients):
    pub, rac = clients
    assert pub.post("/ouvrir", json={"secret": PHRASE}, headers=LAN).status_code == 409
    codes = rac.post("/initialiser", json={"phrase": PHRASE}).json()["codes"]
    assert len(codes) == 5
    assert pub.post("/secrets", json={"compartiment": "box", "nom": "mqtt", "valeur": "s3cr3t-mqtt"}).json() == {"version": 1}
    assert pub.get("/secrets").json()["secrets"][0]["nom"] == "mqtt"
    # Aucune route publique ne rend une valeur.
    assert pub.get("/secrets/box/mqtt/valeur").status_code in (404, 405)
    assert "s3cr3t-mqtt" not in pub.get("/etat").text + pub.get("/journal").text
    assert rac.get("/secrets/box/mqtt/valeur").json() == {"valeur": "s3cr3t-mqtt"}
    assert pub.post("/sceller").json()["ouvert"] is False
    assert pub.get("/secrets").status_code == 423
    assert pub.post("/ouvrir", json={"secret": PHRASE}, headers=LAN).json()["ouvert"] is True
    j = pub.get("/journal").json()
    assert j["integre"] and j["entrees"][-1]["details"]["qui"] == "admin"
    assert j["entrees"][-1]["details"]["origine"] == "lan"


def test_hors_lan_pas_avant_p4(clients, monkeypatch):
    """L'ouverture distante (TOTP frais, alerte) est la phase P4 : en P1, hors LAN
    ou sous politique « second facteur obligatoire », la face publique refuse."""
    pub, rac = clients
    rac.post("/initialiser", json={"phrase": PHRASE})
    pub.post("/sceller")
    r = pub.post("/ouvrir", json={"secret": PHRASE}, headers=WAN)
    assert r.status_code == 403 and "P4" in r.json()["detail"]
    monkeypatch.setattr(second_facteur, "otp_lan", lambda: "obligatoire")
    assert pub.post("/ouvrir", json={"secret": PHRASE}, headers=LAN).status_code == 403
    assert not pub.get("/etat").json()["ouvert"]
    assert pub.get("/journal").json()["entrees"][-1]["details"]["motif"] == "second_facteur"
    # Root, en console, ouvre toujours.
    assert rac.post("/ouvrir", json={"secret": PHRASE}).json()["ouvert"] is True


def test_cinq_echecs_puis_429(clients):
    pub, rac = clients
    rac.post("/initialiser", json={"phrase": PHRASE})
    pub.post("/sceller")
    for _ in range(5):
        assert pub.post("/ouvrir", json={"secret": "mauvaise phrase tres longue"}, headers=LAN).status_code == 403
    r = pub.post("/ouvrir", json={"secret": PHRASE}, headers=LAN)
    assert r.status_code == 429                    # même la bonne phrase attend


def test_racine_serrures_et_codes(clients):
    pub, rac = clients
    rac.post("/initialiser", json={"phrase": PHRASE})
    ident = rac.post("/serrures/phrase", json={"phrase": "seconde phrase bien longue", "libelle": "B"}).json()["id"]
    assert any(s["id"] == ident for s in rac.get("/etat").json()["serrures"])
    nouveaux = rac.post("/serrures/secours").json()["codes"]
    rac.post("/sceller")
    assert rac.post("/ouvrir", json={"secret": nouveaux[0], "genre": "secours"}).status_code == 200
    assert rac.post("/compartiments", json={"id": "gk2"}).status_code == 400   # jamais un compte
    assert rac.post("/compartiments",
                    json={"id": "p-0b6e3c3a-7d0f-4c1e-9a55-3f2a1b8c9d10"}).status_code == 200


def test_le_coffre_n_est_jamais_monte_dans_l_agregateur():
    """Monté dans l'agrégateur, la MK vivrait dans la mémoire de tous les modules."""
    from pathlib import Path
    racine = Path(__file__).resolve().parents[3]
    toml = (racine / "packages" / "secubox-aggregator").rglob("aggregator.toml*")
    for f in toml:
        assert '"vault"' not in f.read_text(), f
    postinst = (racine / "packages" / "secubox-vault" / "debian" / "postinst").read_text()
    assert "aggregator.toml" in postinst and "vault" in postinst
