# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3702 tâche 5 — API des macros : catalogue fermé, flotte et groupes, enregistrement validé (400 hors liste), macros livrées
en lecture seule, simulation sans effet."""
import pytest
from fastapi.testclient import TestClient

from secubox_core import auth

from pilotage.flotte import groupes, materiel
from pilotage.macros import LIVREES
from pilotage.operations import CATALOGUE
from outils import GK2, GK5, releve_gk5
from test_operations_api import Monde

P = "Device."
ETAPES = [{"type": "releve", "duree_s": 60, "nom": "avant"},
          {"type": "condition", "mesure": "services_en_echec", "releve": "avant", "op": ">", "seuil": 0, "alors": "arreter"},
          {"type": "action", "action": "reboot"}]


def modele(nom):
    return {"results": [{"path": "Device.", "params": {P + "DeviceInfo.ModelName": nom}}]}


@pytest.fixture
def m(tmp_path):
    w = Monde(tmp_path)
    w.s.macros_livrees_installer(LIVREES)
    w.s.vu(GK5, {})
    w.s.inventaire_enregistrer(GK5, modele("Globalscale MOCHAbin"))
    return w


def test_toutes_les_routes_console_exigent_un_jwt(tmp_path):
    w = Monde(tmp_path, jwt=False)
    c = TestClient(w.app)
    for methode, url in (("get", "/catalogue"), ("get", "/flotte"), ("get", "/macros"), ("get", "/macros/m-1"), ("post", "/macros"),
                         ("put", "/macros/m-1"), ("delete", "/macros/m-1"), ("post", "/macros/m-1/copier"),
                         ("post", "/macros/m-1/simuler")):
        assert c.request(methode, url, json={}).status_code == 401, url
    vues = 0
    for r in w.app.routes:
        if getattr(r, "dependant", None) and r.path.startswith(("/catalogue", "/flotte", "/macros", "/executions")):
            vues += 1
            assert any(d.call is auth.require_jwt for d in r.dependant.dependencies), r.path
    assert vues >= 9


def test_catalogue_liste_fermee(m):
    cat = TestClient(m.app).get("/catalogue").json()
    assert [a["cle"] for a in cat] == sorted(CATALOGUE)
    par = {a["cle"]: a for a in cat}
    assert par["reboot"]["forte"] is True and par["maj-paquets"]["forte"] is False
    assert par["service-redemarrer"]["parametres"] == ["unite"]
    assert par["renommer"]["macro"] is False and all(a["macro"] for k, a in par.items() if k != "renommer")


def test_flotte_groupes(m):
    gk4 = type(GK5)("gk4", "10.10.0.4", "maillage", None, None)
    gk6 = type(GK5)("gk6", "10.10.0.6", "maillage", None, None)
    m.s.vu(gk4, {})
    m.s.inventaire_enregistrer(gk4, modele("Raspberry Pi 4 Model B"))
    m.s.vu(gk6, {})
    m.s.inventaire_enregistrer(gk6, releve_gk5(interface="distante"))
    m.h.avance(600)                      # gk4 se tait ; gk5 et gk6 reparaissent
    m.s.vu(GK5, {})
    m.s.vu(gk6, {})
    r = TestClient(m.app).get("/flotte").json()
    par = {b["nom"]: b for b in r["boxes"]}
    assert par["gk5"]["materiel"] == "MOCHAbin" and par["gk5"]["cochable"] is True
    assert par["gk4"]["materiel"] == "RPi" and par["gk4"]["cochable"] is False and par["gk4"]["en_ligne"] is False
    assert r["groupes"]["materiel"]["MOCHAbin"] == ["maillage:gk5"] and r["groupes"]["materiel"]["RPi"] == ["maillage:gk4"]
    assert r["groupes"]["interface"]["legeres"] == ["maillage:gk6"]
    assert r["groupes"]["etat"]["muettes"] == ["maillage:gk4"] and "maillage:gk5" in r["groupes"]["etat"]["en_ligne"]


def test_materiel_et_groupes_purs():
    assert [materiel(x) for x in ("Globalscale MOCHAbin", "RASPBERRY Pi 5", "ESPRESSObin v7", "x", None)] == \
        ["MOCHAbin", "RPi", "ESPRESSObin", "autre", "autre"]
    g = groupes([{"cle": "a", "modele": None, "interface": "locale", "en_ligne": True}])
    assert g == {"materiel": {"autre": ["a"]}, "interface": {"legeres": [], "locales": ["a"]}, "etat": {"en_ligne": ["a"], "muettes": []}}


def test_enregistrer_macro_400_hors_liste(m):
    c = TestClient(m.app)
    for corps in ({"nom": "Essai", "etapes": [{"type": "shell", "cmd": "id"}]},
                  {"nom": "a(b)", "etapes": ETAPES[:1]},
                  {"nom": "Essai", "etapes": [{"type": "action", "action": "renommer", "args": {"nom": "x"}}]},
                  {"nom": "Essai", "etapes": []}):
        assert c.post("/macros", json=corps).status_code == 400, corps
    assert [x for x in m.s.macros() if not x["livree"]] == [] and m.lignes == []


def test_enregistrer_programmation_refusee(m):
    c = TestClient(m.app)
    assert c.post("/macros", json={"nom": "Nuit", "etapes": ETAPES, "cibles": ["gk5"], "programmation": {"quotidien": "03:00"}}).status_code == 400
    client = type(GK5)("lgm", "10.64.0.9", "autoload", "acme", "actif")
    m.s.vu(client, {})
    r = c.post("/macros", json={"nom": "Nuit", "etapes": ETAPES[:1], "cibles": [client.cle], "programmation": {"quotidien": "03:00"}})
    assert r.status_code == 400
    assert c.post("/macros", json={"nom": "Nuit", "etapes": ETAPES[:1], "cibles": ["gk5"], "programmation": {"quotidien": "03:00"}}).status_code == 201
    assert len([x for x in m.s.macros() if not x["livree"]]) == 1 and len(m.lignes) == 1


def test_enregistrer_cible_inconnue_et_trop_de_cibles(m):
    c = TestClient(m.app)
    assert c.post("/macros", json={"nom": "X", "etapes": ETAPES[:1], "cibles": ["fantome"]}).status_code == 404
    assert c.post("/macros", json={"nom": "X", "etapes": ETAPES[:1], "cibles": ["gk5"] * 33}).status_code == 422
    assert c.post("/macros", json={"nom": "X", "etapes": ETAPES[:1], "extra": 1}).status_code == 422


def test_enregistrer_puis_lire_cibles_par_cle(m):
    c = TestClient(m.app)
    r = c.post("/macros", json={"nom": "Essai", "etapes": ETAPES, "cibles": ["gk5"]})
    assert r.status_code == 201
    mid = r.json()["id"]
    macro = c.get(f"/macros/{mid}").json()
    assert macro["cibles"] == ["maillage:gk5"] and macro["nom"] == "Essai" and macro["livree"] is False
    assert [x["id"] for x in c.get("/macros").json()][:4] == [x["id"] for x in LIVREES]
    (evt, champs), = m.lignes
    assert evt == "pilotage_macro" and champs["evenement"] == "enregistrement" and champs["macro"] == mid and champs["acteur"] == "alice"
    assert c.get("/macros/m-inconnu").status_code == 404


def test_modifier_et_supprimer_auditent(m):
    c = TestClient(m.app)
    mid = c.post("/macros", json={"nom": "Essai", "etapes": ETAPES[:1]}).json()["id"]
    assert c.put(f"/macros/{mid}", json={"nom": "Autre", "etapes": ETAPES[:1], "cibles": ["gk5"]}).status_code == 200
    assert c.put(f"/macros/{mid}", json={"nom": "Autre", "etapes": [{"type": "shell"}]}).status_code == 400
    assert c.get(f"/macros/{mid}").json()["nom"] == "Autre"
    assert c.delete(f"/macros/{mid}").status_code == 200 and c.get(f"/macros/{mid}").status_code == 404
    assert [x[1]["evenement"] for x in m.lignes] == ["enregistrement", "enregistrement", "suppression"]


def test_audit_en_panne_pas_de_changement(m):
    c = TestClient(m.app)
    mid = c.post("/macros", json={"nom": "Essai", "etapes": ETAPES[:1]}).json()["id"]
    m.audit_ko = True
    assert c.post("/macros", json={"nom": "Deux", "etapes": ETAPES[:1]}).status_code == 503
    assert c.put(f"/macros/{mid}", json={"nom": "Autre", "etapes": ETAPES[:1]}).status_code == 503
    assert c.delete(f"/macros/{mid}").status_code == 503
    assert [x["nom"] for x in m.s.macros() if not x["livree"]] == ["Essai"]


def test_livree_403_et_copie(m):
    c = TestClient(m.app)
    lid = "livree:mise-a-jour-sure"
    assert c.put(f"/macros/{lid}", json={"nom": "X", "etapes": ETAPES[:1]}).status_code == 403
    assert c.delete(f"/macros/{lid}").status_code == 403
    assert m.lignes == []
    r = c.post(f"/macros/{lid}/copier")
    assert r.status_code == 201
    copie = c.get(f"/macros/{r.json()['id']}").json()
    assert copie["nom"] == "Mise à jour sûre copie" and copie["livree"] is False and copie["programmation"] is None
    assert copie["etapes"] == c.get(f"/macros/{lid}").json()["etapes"]


def test_copie_tronquee_a_60(m):
    c = TestClient(m.app)
    mid = c.post("/macros", json={"nom": "n" * 60, "etapes": ETAPES[:1], "programmation": {"quotidien": "03:00"}}).json()["id"]
    copie = c.get(f"/macros/{c.post(f'/macros/{mid}/copier').json()['id']}").json()
    assert copie["nom"] == "n" * 60 and copie["programmation"] is None


def test_simuler_sans_rien_envoyer(m):
    c = TestClient(m.app)
    mid = c.post("/macros", json={"nom": "Essai", "etapes": ETAPES}).json()["id"]
    avant = list(m.lignes)
    r = c.post(f"/macros/{mid}/simuler", json={"box": "gk5"}).json()
    assert r["forte_requise"] is True and r["etapes"][2]["coupure"] == "redémarrage" and r["etapes"][2]["forte"] is True
    assert r["cle"] == "maillage:gk5" and r["en_ligne"] is True and r["cliente"] is False and r["support_requis"] is False
    assert [e["resume"] for e in r["etapes"]][:2] == ["relevé 60 s « avant »", "si services en échec (avant) > 0 alors arrêter"]
    assert r["etapes"][2]["resume"] == "reboot" and r["duree_totale_s"] == sum(e["duree_estimee_s"] for e in r["etapes"]) == 70 + 120
    assert m.f.en_attente(GK5.cle) == 0 and m.lignes == avant
    assert [x for x in m.s.executions()] == []
    assert c.post(f"/macros/{mid}/simuler", json={"box": "fantome"}).status_code == 404
    assert c.post(f"/macros/{mid}/simuler", json={}).status_code == 422


def test_box_porte_les_noms_des_services_en_echec(m):
    rel = releve_gk5(failed=1)
    rel["results"][0]["params"][P + "X_SECUBOX_Services.1.ActiveState"] = "failed"
    m.s.inventaire_enregistrer(GK5, rel)
    b = TestClient(m.app).get("/boxes/gk5").json()
    assert b["services_en_echec_noms"] == ["secubox-hub.service"]
