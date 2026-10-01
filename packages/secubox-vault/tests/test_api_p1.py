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


def test_hors_lan_second_facteur_par_l_agregateur(clients, monkeypatch):
    """P4 : hors LAN, l'ouverture exige le TOTP — vérifié par l'agrégateur, qui
    le signale par X-SecuBox-Second-Facteur. Chaque ouverture distante alerte."""
    pub, rac = clients
    alertes = []
    from secubox_core import courriel
    monkeypatch.setattr(courriel, "adresse_de_la_box", lambda: "gk2@secubox.in")
    monkeypatch.setattr(courriel, "envoie", lambda dest, sujet, corps: alertes.append((dest, sujet)) or {"ok": True})
    rac.post("/initialiser", json={"phrase": PHRASE})
    pub.post("/sceller")
    r = pub.post("/ouvrir", json={"secret": PHRASE}, headers=WAN)
    assert r.status_code == 401 and "second facteur" in r.json()["detail"]
    r = pub.post("/ouvrir", json={"secret": PHRASE}, headers={**WAN, "X-SecuBox-Second-Facteur": "verifie"})
    assert r.status_code == 200 and r.json()["ouvert"]
    import time as _t
    for _ in range(50):
        if alertes:
            break
        _t.sleep(0.02)
    assert alertes == [("gk2@secubox.in", "[SecuBox] Coffre ouvert à distance")]
    entrees = [e for e in pub.get("/journal").json()["entrees"] if e["evt"] == "ouverture"]
    assert entrees[-1]["details"]["origine"] == "distante"
    # LAN sous politique « obligatoire » : même exigence.
    pub.post("/sceller")
    monkeypatch.setattr(second_facteur, "otp_lan", lambda: "obligatoire")
    assert pub.post("/ouvrir", json={"secret": PHRASE}, headers=LAN).status_code == 401
    assert pub.post("/ouvrir", json={"secret": PHRASE},
                    headers={**LAN, "X-SecuBox-Second-Facteur": "verifie"}).status_code == 200


def test_cle_d_appareil_webauthn_prf(clients):
    """P4 : une clé d'appareil (sortie PRF) ouvre le Coffre sans phrase."""
    import base64, os
    b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    pub, rac = clients
    rac.post("/initialiser", json={"phrase": PHRASE})
    sel = pub.post("/serrures/appareil/preparer").json()["sel"]
    prf = os.urandom(32)
    cred = b64u(os.urandom(32))
    r = pub.post("/serrures/appareil", json={"cred_id": cred, "sel": sel, "prf": b64u(prf), "libelle": "clé FIDO"})
    assert r.status_code == 200
    ident = r.json()["id"]
    assert pub.get("/serrures/appareil").json()["appareils"] == [{"id": ident, "cred_id": cred, "sel": sel, "libelle": "clé FIDO"}]
    assert pub.post("/serrures/appareil", json={"cred_id": cred, "sel": sel, "prf": b64u(prf)}).status_code == 400
    pub.post("/sceller")
    assert pub.post("/ouvrir", json={"genre": "appareil", "cred_id": cred, "secret": b64u(os.urandom(32))},
                    headers=LAN).status_code == 403
    r = pub.post("/ouvrir", json={"genre": "appareil", "cred_id": cred, "secret": b64u(prf)}, headers=LAN)
    assert r.status_code == 200 and r.json()["ouvert"]
    assert pub.delete(f"/serrures/appareil/{ident}").json() == {"retiree": True}
    phrase_id = next(x["id"] for x in pub.get("/etat").json()["serrures"] if x["genre"] == "phrase")
    assert pub.delete(f"/serrures/appareil/{phrase_id}").status_code == 404   # jamais une phrase


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
