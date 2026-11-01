# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 5b (#3374), passe 2 : B1 découvertes récentes à l'ouverture, I1 même taxonomie que le moteur (corrections manuelles), I2 « vu /
plus tard » pour les découvertes sans domaine, m1 purge avant plafond, m2 rejeu sans refus ni doublon, marquage vérifié, audit `annule`,
m3 états mis à jour, m4 taxonomie en cache, m5 candidats des seuls appareils guidés."""
import json
import os
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_assistant as A, dnstv_dpi as D, dnstv_regles as R, dnstv_taxonomie as T

MAC = "aa:bb:cc:00:00:01"
LISTES = Path(__file__).resolve().parents[1] / "lists"
T0 = 1_800_000_000


@pytest.fixture
def client(tmp_path, monkeypatch):
    from secubox_core import auth
    from api import dnstv_lot5_routes as L
    from api import dnstv_routes as r
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", LISTES)
    A.vider_cache()
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC}]}, tmp_path)
    audits = []
    monkeypatch.setattr(r, "_ctl_entree", lambda action, entree: audits.append((action, json.loads(entree))))
    app = FastAPI()
    app.include_router(L.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(app)
    c.audits, c.dossier = audits, tmp_path
    return c


def _decouvertes(dossier, n, type_="repli"):
    m = D.MagasinDPI(dossier / "dpi-appareils.db")
    now = int(time.time())
    m.ajouter_decouvertes(MAC, [{"type": type_, "domaine": f"d{i}.example.com" if type_ == "repli" else f"203.0.113.{i % 250}:{1000 + i}",
                                 "ts": now - 1000 + i, "refus_ts": now - 1003 + i, "confiance": 70} for i in range(n)])
    return m


# ── B1 ──
def test_b1_ouverture_rend_les_plus_recentes_puis_curseur_croissant(client):
    _decouvertes(client.dossier, 120)
    j = client.get("/adblock-tv/protection/direct?depuis=0&limite=50").json()
    ids = [d["id"] for d in j["decouvertes"]]
    assert ids == list(range(71, 121)) and j["dernier_id"] == 120
    D.MagasinDPI(client.dossier / "dpi-appareils.db").ajouter_decouvertes(MAC, [{"type": "repli", "domaine": "neuf.example.com", "ts": 1,
                                                                                "refus_ts": 1, "confiance": 70}])
    assert [d["id"] for d in client.get("/adblock-tv/protection/direct?depuis=120").json()["decouvertes"]] == [121]


# ── I1 ──
def _corriger(dossier, domaine, categorie):
    T.ecrire_manuelles(T.corriger({}, domaine, None, categorie, T0), dossier)


def test_i1_domaine_reclasse_protege_exige_force(client):
    _corriger(client.dossier, "relais-pub.example.net", "STREAMING")
    r = client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": "relais-pub.example.net", "choix": "bloquer"})
    assert r.status_code == 409 and "protégée" in r.json()["detail"]


def test_i1_domaine_declasse_ne_demande_plus_force(client):
    _corriger(client.dossier, "imasdk.googleapis.com", "PUBLICITE")
    r = client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": "imasdk.googleapis.com", "choix": "bloquer"})
    assert r.status_code == 200


def test_i1_api_et_moteur_partagent_la_meme_fonction(client):
    src = (Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-auto").read_text()
    assert "dnstv_assistant.taxonomie(regles=regles)" in src


# ── I2 ──
def test_i2_vu_plus_tard_pour_une_decouverte_sans_domaine(client):
    _decouvertes(client.dossier, 1, "sans-dns")
    d = client.get("/adblock-tv/protection/direct").json()["decouvertes"][0]
    assert d["actionnable"] is False and d["vu_possible"] is True
    r = client.post("/adblock-tv/protection/assistant/vu", json={"mac": MAC, "decouverte": d["id"]})
    assert r.status_code == 200 and A.charger(client.dossier)["vus"] == [{"id": d["id"], "mac": MAC}]
    assert client.audits[-1][1] == {"acteur": "admin", "origine": "admin", "geste": "assistant", "cibles": ["TV salon"], "minutes": None,
                                    "domaine": None, "type": "vu", "force": False}
    assert client.get("/adblock-tv/protection/direct").json()["decouvertes"][0]["vu"] is True


def test_i2_le_moteur_marque_les_vus(tmp_path):
    m = _decouvertes(tmp_path, 1, "sans-dns")
    c = A.vide()
    A.marquer_vu(c, MAC, 1)
    marques = A.consommer(c, {"clients": []}, R.Regles(), [], [], T.Taxonomie.depuis_dossier(LISTES), T0)["marques"]
    assert marques == [(1, "plus-tard", MAC, None)] and c["vus"] == []
    m.marquer_id(1, "plus-tard", MAC, None)
    assert m.decouvertes()[0]["etat"] == "plus-tard"


def test_i2_audit_root_accepte_vu_sans_domaine():
    import importlib.machinery
    import importlib.util
    ch = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-tv"
    lo = importlib.machinery.SourceFileLoader("tvctl_p2", str(ch))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("tvctl_p2", lo))
    lo.exec_module(mod)
    bon = {"acteur": "admin", "origine": "admin", "geste": "assistant", "cibles": ["TV salon"], "minutes": None, "domaine": None,
           "type": "vu", "force": False}
    assert mod._enregistrement_protection(bon) and not mod._enregistrement_protection(dict(bon, domaine="x.example.com"))
    assert not mod._enregistrement_protection(dict(bon, type="bloquer"))


# ── m1 ──
def test_m1_purge_avant_plafond_et_message_juste():
    c = A.vide()
    for i in range(A.FILE_MAX):
        x = A.ajouter(c, MAC, "TV salon", f"d{i}.example.com", "plus-tard", False, None, "admin", T0)
        x.update(etat="applique", applique=T0)
    A.ajouter(c, MAC, "TV salon", "neuf.example.com", "plus-tard", False, None, "admin", T0 + 86400 + 10)    # purgée d'abord
    c2 = A.vide()
    for i in range(A.FILE_MAX):
        x = A.ajouter(c2, MAC, "TV salon", f"d{i}.example.com", "plus-tard", False, None, "admin", T0)
        x.update(etat="applique", applique=T0)
    with pytest.raises(A.ErreurPlafond, match="24 h"):
        A.ajouter(c2, MAC, "TV salon", "neuf.example.com", "plus-tard", False, None, "admin", T0 + 60)


# ── m2 ──
def test_m2_rejeu_d_une_exception_deja_posee_est_applique_sans_doublon():
    e = {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC}]}
    r, c = R.Regles(), A.vide()
    taxo = T.Taxonomie.depuis_dossier(LISTES)
    A.ajouter(c, MAC, "TV salon", "relais-pub.example.net", "bloquer", False, None, "admin", T0)
    res = A.consommer(c, e, r, [], [], taxo, T0)
    c2 = A.vide()                                                     # moteur arrêté avant d'écrire la file : rejeu
    A.ajouter(c2, MAC, "TV salon", "relais-pub.example.net", "bloquer", False, None, "admin", T0)
    res2 = A.consommer(c2, e, r, res["exceptions"], [], taxo, T0 + 60)
    assert c2["file"][0]["etat"] == "applique" and res2["appliquees"] == [] and res2["dns"] is False
    assert len(res2["exceptions"]) == 1 and len(res["appliquees"]) == 1


# ── marquer_id vérifie MAC et domaine ──
def test_marquer_id_verifie_mac_et_domaine(tmp_path):
    m = _decouvertes(tmp_path, 1)
    m.marquer_id(1, "confirmee", "aa:bb:cc:00:00:99", "d0.example.com")
    m.marquer_id(1, "confirmee", MAC, "autre.example.com")
    assert m.decouvertes()[0]["etat"] == "nouvelle"
    m.marquer_id(1, "confirmee", MAC, "d0.example.com")
    assert m.decouvertes()[0]["etat"] == "confirmee"


# ── audit annule après échec d'écriture ──
def test_audit_annule_si_la_file_n_est_pas_ecrite(client, monkeypatch):
    def casse(*a, **k):
        raise OSError("disque plein")
    monkeypatch.setattr(A, "ecrire", casse)
    r = client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": "x.example.com", "choix": "plus-tard"})
    assert r.status_code == 503 and [a[1]["geste"] for a in client.audits] == ["assistant", "annule"]


# ── m3 ──
def test_m3_etats_des_decouvertes_deja_vues(client):
    m = _decouvertes(client.dossier, 3)
    m.marquer_id(2, "legitime", MAC, "d1.example.com")
    j = client.get("/adblock-tv/protection/direct?depuis=3").json()
    assert j["decouvertes"] == [] and j["etats"] == {"2": "legitime"}


# ── m4 ──
def test_m4_taxonomie_en_cache_rechargee_sur_mtime(client):
    t1 = A.taxonomie()
    assert A.taxonomie() is t1
    _corriger(client.dossier, "x.example.com", "STREAMING")
    f = client.dossier / T.FICHIER
    os.utime(f, (time.time() + 5, time.time() + 5))
    t2 = A.taxonomie()
    assert t2 is not t1 and t2.classer("x.example.com")["categorie"] == "STREAMING"


# ── m5 ──
def test_m5_candidats_des_seuls_appareils_guides(client):
    r = R.Regles()
    r.proposer("tv-salon", "pub.example.com", 70, "faible", int(time.time()))
    R.ecrire(r, client.dossier)
    assert client.get("/adblock-tv/protection/direct").json()["candidats"] == []
    client.post("/adblock-tv/protection/assistant/guide", json={"mac": MAC, "actif": True})
    assert [c["domaine"] for c in client.get("/adblock-tv/protection/direct").json()["candidats"]] == ["pub.example.com"]
