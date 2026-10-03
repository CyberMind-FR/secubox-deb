# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1959 : routes de détection, d'ignorance, de puits et de profil agrégé."""
import inspect
import time

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from api import dnstv, dnstv_ajout, dnstv_profil, dnstv_regles as R
from test_dnstv_ctl_api import api, ctl, monde  # noqa: F401  (fixtures)

MAC = "38:07:16:94:fb:5b"
V6 = "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"
T = int(time.time())
ETAT = {"actif": True, "ajout_auto": True, "clients": [
    {"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"},
    {"ip": "192.168.1.128", "nom": "TV fb5b", "mode": "auto", "mac": MAC, "origine": "auto", "ajoute": T - 100, "preuve": "12 requêtes vers fwmrm.net"},
    {"ip": V6, "nom": "TV fb5b", "mode": "auto", "mac": MAC, "origine": "auto", "ajoute": T - 100, "preuve": "12 requêtes vers fwmrm.net"}]}


@pytest.fixture
def donnees(monde):
    dnstv.ecrire_etat(ETAT, monde["etat"])
    r = R.Regles()
    for app, dom in (("tv-fb5b", "c.2mdn.net"), ("tv-fb5b", "videos-pub.ftv-publicite.fr"), ("tv-banc", "c.2mdn.net")):
        rid = r.proposer(app, dom, 100, "faible", T, origine="auto", motif="profil de base")["id"]
        r.transiter(rid, "essai", "auto", "profil de base", T)
        r.transiter(rid, "confirme", "auto", "profil de base", T)
    R.ecrire(r, monde["etat"])
    dnstv_ajout.ecrire_suivi({"ajouts": [T - 100], "dernier_changement": T - 100}, monde["etat"])
    return monde


@pytest.fixture
def faux_api(donnees, monkeypatch):
    """API avec un faux contrôleur dont l'échec se commande par donnees["echec"] : pour les retours arrière."""
    from secubox_core import auth
    from api import dnstv_routes as routes

    def appel(action):
        if donnees.get("echec"):
            raise HTTPException(502, "contrôleur en échec")
        donnees.setdefault("appels", []).append(action)
        return {"ok": True}
    monkeypatch.setattr(routes, "_ctl", appel)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "admin"}
    return TestClient(app), donnees


def etat_disque(monde):
    return dnstv.lire_etat(monde["etat"])[0]


def test_detection_regroupe_les_adresses_par_appareil_avec_preuve_et_plafond(api, donnees):
    j = api.get("/adblock-tv/auto/detection").json()
    assert j["ajout_auto"] is True and j["mode_defaut"] == "auto" and j["ignores"] == []
    par = {a["nom"]: a for a in j["appareils"]}
    assert sorted(par["TV fb5b"]["adresses"]) == sorted(["192.168.1.128", V6]) and par["TV fb5b"]["origine"] == "auto"
    assert par["TV fb5b"]["mac"] == MAC and "fwmrm.net" in par["TV fb5b"]["preuve"] and par["TV fb5b"]["puits"] is True
    assert par["TV banc"]["origine"] == "admin" and par["TV banc"]["mac"] == ""
    assert j["plafond"] == {"max_par_jour": 3, "ajouts_24h": 1}


def test_reglage_valide_ecrit_l_etat_et_applique(api, donnees):
    r = api.post("/adblock-tv/auto/detection/reglage", json={"ajout_auto": False, "mode_defaut": "observe"})
    assert r.status_code == 200 and r.json()["application"]["ok"] is True
    e = etat_disque(donnees)
    assert e["ajout_auto"] is False and e["mode_defaut"] == "observe"
    assert api.post("/adblock-tv/auto/detection/reglage", json={"ajout_auto": True}).status_code == 200 and etat_disque(donnees)["mode_defaut"] == "observe"


def test_reglage_invalide_refuse(api, donnees):
    for corps in ({"mode_defaut": "detruire"}, {"ajout_auto": "peut-etre"}, {}):
        assert api.post("/adblock-tv/auto/detection/reglage", json=corps).status_code == 422


def test_reglage_echec_du_controleur_retablit_l_etat(faux_api):
    c, donnees = faux_api
    donnees["echec"] = True
    avant = etat_disque(donnees)
    assert c.post("/adblock-tv/auto/detection/reglage", json={"ajout_auto": False}).status_code == 502
    assert etat_disque(donnees) == avant


def test_ignorer_retire_l_appareil_ignore_sa_mac_et_retire_ses_regles(api, donnees):
    r = api.post("/adblock-tv/auto/appareils/TV fb5b/ignorer")
    assert r.status_code == 200 and r.json()["retire"] == 2
    e = etat_disque(donnees)
    assert [c["nom"] for c in e["clients"]] == ["TV banc"] and e["ignores"] == [MAC]
    regles = R.charger(donnees["etat"])
    assert regles.actives("tv-fb5b") == [] and regles.actives("tv-banc") == ["c.2mdn.net"]        # seul l'appareil visé est touché
    assert "tv-fb5b" not in donnees["conf"].read_text() and "TV fb5b" not in donnees["conf"].read_text()


def test_ignorer_un_appareil_declare_sans_mac_n_ajoute_pas_de_mac(api, donnees):
    assert api.post("/adblock-tv/auto/appareils/TV banc/ignorer").status_code == 200
    assert etat_disque(donnees)["ignores"] == []


def test_ignorer_inconnu_ou_hostile(api, donnees):
    for nom in ("inconnu", "..%2Fx", "A" * 200, "x%0Aserver:"):
        assert api.post(f"/adblock-tv/auto/appareils/{nom}/ignorer").status_code in (404, 422)
    assert len(etat_disque(donnees)["clients"]) == 3


def test_ignorer_echec_du_controleur_retablit_etat_et_regles(faux_api):
    c, donnees = faux_api
    donnees["echec"] = True
    e0, r0 = etat_disque(donnees), R.charger(donnees["etat"]).liste()
    assert c.post("/adblock-tv/auto/appareils/TV fb5b/ignorer").status_code == 502
    assert etat_disque(donnees) == e0 and R.charger(donnees["etat"]).liste() == r0


def test_puits_bascule_et_le_rendu_suit(api, donnees):
    r = api.post("/adblock-tv/auto/appareils/TV banc/puits", json={"actif": False})
    assert r.status_code == 200 and all(c.get("puits") is False for c in etat_disque(donnees)["clients"] if c["nom"] == "TV banc")
    bloc = donnees["conf"].read_text().split('name: "sbx-tv-auto-tv-banc"')[1].split("view:")[0]
    assert 'local-zone: "." transparent' in bloc and "view-first" not in bloc
    assert api.post("/adblock-tv/auto/appareils/TV banc/puits", json={"actif": True}).status_code == 200
    bloc = donnees["conf"].read_text().split('name: "sbx-tv-auto-tv-banc"')[1].split("view:")[0]
    assert "view-first: yes" in bloc


def test_puits_inconnu_ou_hors_mode_auto(api, donnees):
    assert api.post("/adblock-tv/auto/appareils/inconnu/puits", json={"actif": False}).status_code == 404
    e = etat_disque(donnees)
    e["clients"].append({"ip": "192.168.1.9", "nom": "Observe", "mode": "observe"})
    dnstv.ecrire_etat(e, donnees["etat"])
    assert api.post("/adblock-tv/auto/appareils/Observe/puits", json={"actif": False}).status_code == 422
    assert api.post("/adblock-tv/auto/appareils/TV banc/puits", json={"actif": "non"}).status_code == 422


def test_profil_graine_agrege_et_effectif(api, donnees):
    dnstv_profil.ecrire_agrege({"pub.example.com": {"appareils": ["tv-a", "tv-b"], "maj": T}}, donnees["etat"])
    j = api.get("/adblock-tv/auto/profil").json()
    assert j["min_appareils"] == 2 and len(j["graine"]) == 35 and j["agrege"]["pub.example.com"]["appareils"] == ["tv-a", "tv-b"]
    eff = {x["domaine"]: x["motif"] for x in j["effectif"]}
    assert eff["c.2mdn.net"] == "profil de base" and eff["pub.example.com"] == "profil agrégé (2 appareils)"


def test_gardes_et_routes_synchrones(donnees):
    from secubox_core import auth
    from api import dnstv_routes as r
    app = FastAPI()
    app.include_router(r.router)
    app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "lecteur"}           # lecture seule : l'écriture reste refusée
    c = TestClient(app)
    assert c.get("/adblock-tv/auto/detection").status_code == 200 and c.get("/adblock-tv/auto/profil").status_code == 200
    for chemin, corps in (("/adblock-tv/auto/detection/reglage", {"ajout_auto": False}), ("/adblock-tv/auto/appareils/TV banc/ignorer", None),
                          ("/adblock-tv/auto/appareils/TV banc/puits", {"actif": False})):
        assert c.post(chemin, json=corps).status_code in (401, 403), chemin
    for nom in ("detection", "detection_reglage", "ignorer_appareil", "puits_appareil", "profil"):
        assert not inspect.iscoroutinefunction(getattr(r, nom)), nom
