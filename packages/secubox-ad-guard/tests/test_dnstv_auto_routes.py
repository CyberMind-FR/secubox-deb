# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Routes d'administration du mode auto (#1954). Les fixtures `monde`/`api` viennent du banc du contrôleur (test_dnstv_ctl_api)."""
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_regles as R
from test_dnstv_ctl_api import api, ctl, monde  # noqa: F401  (fixtures)

ETAT = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}]}
T = int(time.time())


@pytest.fixture
def regles(monde):
    dnstv.ecrire_etat(ETAT, monde["etat"])
    r = R.Regles()
    ids = {"cand": r.proposer("tv-banc", "ad.example.com", 80, "faible", T)["id"],
           "essai": r.proposer("tv-banc", "pub.example.com", 70, "partage", T)["id"],
           "essai2": r.proposer("tv-banc", "pub2.example.com", 60, "faible", T)["id"],
           "autre": r.proposer("autre", "x.example.com", 60, "faible", T)["id"]}
    r.transiter(ids["essai"], "essai", "admin", "", T)
    r.transiter(ids["essai2"], "essai", "admin", "", T)
    r.transiter(ids["autre"], "essai", "admin", "", T)
    R.ecrire(r, monde["etat"])
    return ids


def etat_de(monde, rid):
    return R.charger(monde["etat"]).get(rid)["etat"]


def test_lecture_des_regles_avec_compteurs(api, regles):
    j = api.get("/adblock-tv/auto/regles").json()
    assert j["compteurs"] == {"candidat": 1, "essai": 3} and len(j["regles"]) == 4
    assert [r["domaine"] for r in api.get("/adblock-tv/auto/regles?etat=candidat").json()["regles"]] == ["ad.example.com"]
    assert len(api.get("/adblock-tv/auto/regles?appareil=autre").json()["regles"]) == 1


def test_essayer_un_candidat_applique_a_chaud(api, monde, regles):
    r = api.post(f"/adblock-tv/auto/regles/{regles['cand']}/essayer")
    assert r.status_code == 200 and r.json()["regle"]["etat"] == "essai" and r.json()["application"]["ok"] is True
    assert etat_de(monde, regles["cand"]) == "essai"
    assert 'local-zone: "ad.example.com." always_nxdomain' in monde["conf"].read_text()


def test_confirmer_ne_change_pas_l_effet_dns_mais_est_transmis_au_controleur_pour_l_audit(api, monde, regles):
    r = api.post(f"/adblock-tv/auto/regles/{regles['essai']}/confirmer")
    assert r.status_code == 200 and r.json()["regle"]["etat"] == "confirme" and r.json()["application"]["ok"] is True


def test_confirmer_sans_essai_refuse(api, regles):
    assert api.post(f"/adblock-tv/auto/regles/{regles['cand']}/confirmer").status_code == 422


def test_rejeter_puis_rouvrir(api, monde, regles):
    assert api.post(f"/adblock-tv/auto/regles/{regles['cand']}/rejeter").json()["regle"]["etat"] == "rejete"
    assert api.post(f"/adblock-tv/auto/regles/{regles['cand']}/rouvrir").json()["regle"]["etat"] == "candidat"


def test_retirer_une_regle_en_essai_applique(api, monde, regles):
    r = api.post(f"/adblock-tv/auto/regles/{regles['essai']}/retirer")
    assert r.json()["regle"]["etat"] == "retire" and r.json()["application"]["ok"] is True


def test_ca_ne_marche_plus_retire_les_essais_de_cet_appareil_seulement(api, monde, regles):
    r = api.post("/adblock-tv/auto/appareils/tv-banc/ca-ne-marche-plus")
    assert r.status_code == 200 and r.json()["retirees"] == 2
    assert etat_de(monde, regles["essai"]) == etat_de(monde, regles["essai2"]) == "retire"
    assert etat_de(monde, regles["cand"]) == "candidat" and etat_de(monde, regles["autre"]) == "essai"
    assert api.post("/adblock-tv/auto/appareils/tv-banc/ca-ne-marche-plus").json() == {"retirees": 0, "application": None}


def test_identifiants_et_actions_hostiles(api, regles):
    for rid in ("../x", "A" * 200, "zzzzzzzzzzzz", "123"):
        assert api.post(f"/adblock-tv/auto/regles/{rid}/essayer").status_code in (404, 422)
    assert api.post(f"/adblock-tv/auto/regles/{regles['cand']}/detruire").status_code == 404
    assert api.post("/adblock-tv/auto/regles/abcdefabcdef/essayer").status_code == 404


def test_fichier_de_regles_corrompu_rend_409_sans_trace(api, monde):
    (monde["etat"] / "regles.json").write_text("{pas du json")
    assert api.get("/adblock-tv/auto/regles").status_code == 409


def test_auto_essai_se_regle_par_l_administrateur_et_reste_dans_l_etat(api, monde, regles):
    assert api.get("/adblock-tv/auto/reglage").json()["auto_essai"] is False
    assert api.post("/adblock-tv/auto/reglage/auto-essai", json={"actif": True}).status_code == 200
    assert api.get("/adblock-tv/auto/reglage").json()["auto_essai"] is True
    assert dnstv.lire_etat(monde["etat"])[0]["auto_essai"] is True
    assert api.post("/adblock-tv/auto/reglage/auto-essai", json={"actif": "pas un booleen"}).status_code == 422


def test_les_gardes_d_acces(monde, regles, monkeypatch):
    from secubox_core import auth
    from api import dnstv_routes as r
    app = FastAPI()
    app.include_router(r.router)
    app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "lecteur"}          # lecture seule : l'écriture reste refusée
    c = TestClient(app)
    assert c.get("/adblock-tv/auto/regles").status_code == 200
    assert c.post(f"/adblock-tv/auto/regles/{regles['cand']}/essayer").status_code in (401, 403)
    assert c.post("/adblock-tv/auto/appareils/tv-banc/ca-ne-marche-plus").status_code in (401, 403)
