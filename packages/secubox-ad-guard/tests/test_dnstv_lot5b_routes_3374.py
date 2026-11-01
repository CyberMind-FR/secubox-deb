# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 5b (#3374) : routes de l'assistant — flux « En direct » à curseur, choix différés audités (garde `force`, imasdk), annulation,
apprentissage guidé, compteur agrégé du kiosque. Toutes en require_jwt sauf le compteur (require_personne)."""
import json
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_assistant as A, dnstv_dpi as D, dnstv_regles as R

MAC = "aa:bb:cc:00:00:01"
INCONNUE = "aa:bb:cc:00:00:09"
LISTES = Path(__file__).resolve().parents[1] / "lists"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from secubox_core import auth
    from api import dnstv_lot5_routes as L
    from api import dnstv_routes as r
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", LISTES)
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC}]}, tmp_path)
    now = int(time.time())
    mag = D.MagasinDPI(tmp_path / "dpi-appareils.db")
    mag.ajouter_decouvertes(MAC, [{"type": "repli", "domaine": "metaproxy.francetvpub.fr", "categorie": "PUBLICITE", "ts": now - 97,
                                   "refus_ts": now - 100, "delai_s": 3, "confiance": 70, "raison": "apparu 3 s après le blocage de pagead2"}])
    mag.ajouter_decouvertes(INCONNUE, [{"type": "sans-dns", "domaine": "203.0.113.9:443", "ts": now - 50, "confiance": 80,
                                        "raison": "adresse en dur"}])
    audits = []
    monkeypatch.setattr(r, "_ctl_entree", lambda action, entree: audits.append((action, json.loads(entree))))
    app = FastAPI()
    app.include_router(L.router)
    qui = {"sub": "admin"}
    app.dependency_overrides[auth.require_jwt] = lambda: qui
    app.dependency_overrides[auth.require_personne] = lambda: {"sub": "marie"}
    c = TestClient(app)
    c.audits, c.dossier = audits, tmp_path
    return c


def test_direct_curseur_nom_d_appareil_jamais_une_ip(client):
    j = client.get("/adblock-tv/protection/direct?depuis=0").json()
    d = {x["domaine"]: x for x in j["decouvertes"]}
    assert d["metaproxy.francetvpub.fr"]["appareil"] == "TV salon" and d["metaproxy.francetvpub.fr"]["actionnable"] is True
    assert d["metaproxy.francetvpub.fr"]["categorie"] == "PUBLICITE" and d["metaproxy.francetvpub.fr"]["raison"].startswith("apparu 3 s")
    assert d["203.0.113.9:443"]["appareil"] == "appareil inconnu" and d["203.0.113.9:443"]["actionnable"] is False
    assert j["dernier_id"] == max(x["id"] for x in j["decouvertes"])
    assert client.get(f"/adblock-tv/protection/direct?depuis={j['dernier_id']}").json()["decouvertes"] == []
    assert client.get("/adblock-tv/protection/direct?limite=500").status_code == 422
    assert j["appareils"] == [{"mac": MAC, "nom": "TV salon", "guide": False}]


def test_choix_differe_audite_puis_annulable(client):
    d = client.get("/adblock-tv/protection/direct").json()["decouvertes"][0]
    r = client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": d["domaine"], "choix": "bloquer",
                                                                     "decouverte": d["id"]})
    assert r.status_code == 200 and r.json()["etat"] == "en-attente"
    assert client.audits[-1] == ("audit-protection", {"acteur": "admin", "origine": "admin", "geste": "assistant", "cibles": ["TV salon"],
                                                      "minutes": None, "domaine": d["domaine"], "type": "bloquer", "force": False})
    # sans doublon
    assert client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": d["domaine"], "choix": "legitime"}).status_code == 409
    j = client.get("/adblock-tv/protection/direct?depuis=0").json()
    assert j["file"][0]["etat"] == "en-attente" and {x["domaine"]: x for x in j["decouvertes"]}[d["domaine"]]["action"]["choix"] == "bloquer"
    a = client.post("/adblock-tv/protection/assistant/annuler", json={"id": r.json()["id"]})
    assert a.status_code == 200 and A.charger(client.dossier)["file"] == []
    assert client.audits[-1][1]["geste"] == "assistant-annule"


def test_annulation_refusee_une_fois_appliquee(client):
    r = client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": "x.example.com", "choix": "plus-tard"}).json()
    c = A.charger(client.dossier)
    c["file"][0].update(etat="applique", applique=int(time.time()))
    A.ecrire(c, client.dossier)
    assert client.post("/adblock-tv/protection/assistant/annuler", json={"id": r["id"]}).status_code == 409


def test_imasdk_jamais_bloquable_sans_force(client):
    r = client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": "imasdk.googleapis.com", "choix": "bloquer"})
    assert r.status_code == 409 and "protégée" in r.json()["detail"] and not client.audits
    r = client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": "imasdk.googleapis.com", "choix": "bloquer",
                                                                     "force": True})
    assert r.status_code == 200 and client.audits[-1][1]["force"] is True
    assert client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": "imasdk.googleapis.com",
                                                                        "choix": "legitime"}).status_code == 409   # doublon


def test_parametres_fermes_et_appareil_inconnu(client):
    p = "/adblock-tv/protection/assistant/choix"
    assert client.post(p, json={"mac": MAC, "domaine": "x.example.com", "choix": "durcir"}).status_code == 422
    assert client.post(p, json={"mac": MAC, "domaine": "x.example.com", "choix": "bloquer", "extra": 1}).status_code == 422
    assert client.post(p, json={"mac": "pas-une-mac", "domaine": "x.example.com", "choix": "bloquer"}).status_code == 422
    assert client.post(p, json={"mac": MAC, "domaine": "203.0.113.9:443", "choix": "bloquer"}).status_code == 422
    assert client.post(p, json={"mac": INCONNUE, "domaine": "x.example.com", "choix": "bloquer"}).status_code == 404


def test_audit_impossible_refuse_le_choix(client, monkeypatch):
    from fastapi import HTTPException
    from api import dnstv_routes as r

    def refus(action, entree):
        raise HTTPException(502, "audit refusé")
    monkeypatch.setattr(r, "_ctl_entree", refus)
    assert client.post("/adblock-tv/protection/assistant/choix", json={"mac": MAC, "domaine": "x.example.com", "choix": "bloquer"}).status_code == 502
    assert A.charger(client.dossier)["file"] == []


def test_apprentissage_guide_par_appareil(client):
    assert client.post("/adblock-tv/protection/assistant/guide", json={"mac": MAC, "actif": True}).json() == {"mac": MAC, "guide": True}
    assert A.charger(client.dossier)["guides"] == [MAC] and client.audits[-1][1]["geste"] == "guide"
    assert client.audits[-1][1]["type"] == "active"
    assert client.get("/adblock-tv/protection/direct").json()["appareils"][0]["guide"] is True
    client.post("/adblock-tv/protection/assistant/guide", json={"mac": MAC, "actif": False})
    assert A.charger(client.dossier)["guides"] == [] and client.audits[-1][1]["type"] == "desactive"
    assert client.post("/adblock-tv/protection/assistant/guide", json={"mac": INCONNUE, "actif": True}).status_code == 404


def test_candidats_en_attente_de_validation(client):
    r = R.Regles()
    r.proposer("tv-salon", "pub.example.com", 70, "faible", int(time.time()), motif="repli publicitaire : apparu 2 s après X")
    R.ecrire(r, client.dossier)
    c = client.get("/adblock-tv/protection/direct").json()["candidats"]
    assert c == [{"mac": MAC, "appareil": "TV salon", "domaine": "pub.example.com", "confiance": 70,
                  "raison": "repli publicitaire : apparu 2 s après X", "categorie": c[0]["categorie"], "action": None}]


def test_compteur_du_kiosque_agrege(client):
    r = R.Regles()
    n = r.proposer("tv-salon", "pub.example.com", 70, "faible", int(time.time()))
    r.transiter(n["id"], "essai", "auto", "essai", int(time.time()))
    R.ecrire(r, client.dossier)
    assert client.get("/adblock-tv/protection/usager/appris").json() == {"nouveaux_pisteurs": 1, "jours": 7}


def test_gardes_des_routes():
    from secubox_core import auth
    from api import dnstv_lot5_routes as L
    for x in L.router.routes:
        deps = {d.call for d in x.dependant.dependencies}
        if x.path.endswith("/usager/appris"):
            assert auth.require_personne in deps
        else:
            assert auth.require_jwt in deps, x.path


def test_routes_admin_ouvertes_a_la_page_relayee():
    t = (Path(__file__).resolve().parents[1] / "pilotage" / "routes-ouvertes.d" / "ad-guard.toml").read_text()
    assert "^/adblock-tv/protection/assistant/(choix|annuler|guide)$" in t and "usager/appris" not in t


def test_monte_dans_l_application():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text()
    assert "dnstv_lot5_routes import router" in src
