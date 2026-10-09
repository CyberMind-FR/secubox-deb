# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2174 : panneau simplifié — cartes par appareil, interrupteur vérifié, noms qui ressemblent à une pub."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_simple as S
from test_dnstv_ctl_api import api, ctl, monde  # noqa: F401  (fixtures)

V6 = "2a01:e0a:dec:c4e0:c147:c3cf:6dd7:3429"
ETAT = {"actif": True, "clients": [
    {"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}, {"ip": V6, "nom": "TV banc", "mode": "auto"},
    {"ip": "192.168.1.60", "nom": "Chromecast", "mode": "off"}]}


def test_un_mot_entier_signale_une_pub_pas_une_sous_chaine():
    assert S.ressemble_a_pub("ads-metrics.tvchaine.example")
    assert S.ressemble_a_pub("stats.cdn-videoplayer.example")
    assert S.ressemble_a_pub("loads.example.com") is None and S.ressemble_a_pub("pads.example.com") is None
    assert S.ressemble_a_pub("replay-04.oqee.net") is None


def test_suspects_ignore_bloques_ignores_et_inconnus():
    ev = [{"client": "1.1.1.1", "domaine": d, "decision": dec} for d, dec in (
        ("ads.a.example", "ALLOWED"), ("ads.a.example", "ALLOWED"), ("ads.b.example", "BLOCKED"), ("ads.c.example", "ALLOWED"),
        ("ads.d.example", "ALLOWED"), ("video.e.example", "ALLOWED"))]
    ev.append({"client": "9.9.9.9", "domaine": "ads.z.example", "decision": "ALLOWED"})            # appareil non suivi
    r = S.suspects(ev, {"1.1.1.1": "TV"}, {"ads.c.example"}, {"ads.d.example"})
    assert [(x["domaine"], x["requetes"]) for x in r] == [("ads.a.example", 2)]


def test_les_cartes_regroupent_les_adresses_et_comptent_les_blocages():
    c = S.appareils(ETAT, {"192.168.1.95": 3, V6: 4}, {})
    assert [(x["nom"], x["adresses"], x["protege"], x["blocages_jour"]) for x in c] == [("TV banc", 2, True, 7), ("Chromecast", 1, False, 0)]


def test_une_carte_dont_une_adresse_n_est_pas_auto_n_est_pas_protegee():
    e = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}, {"ip": V6, "nom": "TV banc", "mode": "block"}]}
    assert S.appareils(e, {}, {})[0]["protege"] is False


def test_la_verification_voit_une_adresse_restee_dans_l_ancienne_vue():
    e = dnstv.valider_etat(ETAT)
    bon = dnstv.rendre_unbound(e, {}, {})
    assert S.verifier_application(e, "TV banc", bon) is None
    perime = bon.replace(f"access-control-view: {V6}/128 sbx-tv-auto-tv-banc", f"access-control-view: {V6}/128 sbx-tv-block")
    assert V6 in S.verifier_application(e, "TV banc", perime)
    assert S.verifier_application(e, "TV banc", "") is not None


@pytest.fixture
def client(monde, monkeypatch, tmp_path):
    from secubox_core import auth
    from api import dnstv_routes as routes
    dnstv.ecrire_etat(ETAT, monde["etat"])
    conf = tmp_path / "94.conf"
    monkeypatch.setattr(dnstv, "CONF_UNBOUND", conf)
    monde["conf"] = conf

    def appel(action):
        monde.setdefault("appels", []).append(action)
        if not monde.get("sans_ecriture"):
            conf.write_text(dnstv.rendre_unbound(dnstv.lire_etat(monde["etat"])[0], {}, {}), encoding="utf-8")
        return {"ok": True}
    monkeypatch.setattr(routes, "_ctl", appel)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "admin"}
    return TestClient(app), monde


def test_l_interrupteur_protege_et_verifie(client):
    c, m = client
    r = c.post("/adblock-tv/simple/appareils/Chromecast/protection", json={"actif": True})
    assert r.status_code == 200 and r.json()["verifie"] is True
    assert dnstv.lire_etat(m["etat"])[0]["clients"][2]["mode"] == "auto"
    r = c.post("/adblock-tv/simple/appareils/Chromecast/protection", json={"actif": False})
    assert r.json()["verifie"] is True and dnstv.lire_etat(m["etat"])[0]["clients"][2]["mode"] == "off"


def test_un_changement_perdu_est_signale_au_lieu_de_passer_sous_silence(client):
    c, m = client
    m["sans_ecriture"] = True                                         # le contrôleur « réussit » mais le filtre n'est pas mis à jour
    r = c.post("/adblock-tv/simple/appareils/Chromecast/protection", json={"actif": True})
    assert r.status_code == 200 and r.json()["verifie"] is False and r.json()["ecart"]


def test_appareil_inconnu_404(client):
    c, _ = client
    assert c.post("/adblock-tv/simple/appareils/Inconnu/protection", json={"actif": True}).status_code == 404


def test_simple_liste_les_cartes(client):
    c, _ = client
    j = c.get("/adblock-tv/simple").json()
    assert j["protegees"] == 1 and [x["nom"] for x in j["appareils"]] == ["TV banc", "Chromecast"]


def test_marquer_legitime_retire_le_nom_des_suspects(client):
    c, m = client
    assert c.post("/adblock-tv/simple/suspects/legitime", json={"domaine": "ads.a.example"}).json()["ignores"] == 1
    assert c.post("/adblock-tv/simple/suspects/legitime", json={"domaine": "pas un nom"}).status_code == 422
    assert c.get("/adblock-tv/simple/suspects").json()["suspects"] == []


def test_un_appareil_declare_sans_mode_est_en_auto_par_defaut(client):
    c, m = client
    assert c.post("/adblock-tv/clients", json={"ip": "192.168.1.77", "nom": "Neuve"}).status_code == 200
    assert [x["mode"] for x in dnstv.lire_etat(m["etat"])[0]["clients"] if x["nom"] == "Neuve"] == ["auto"]
