# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import asyncio
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from secubox_core import auth

from api.main import creer_app_admin
from pilotage.files import Files
from pilotage.inventaire import Inventaire
from pilotage.stockage import StockageSqlite
from outils import GK2, GK5, GK5_AUTOLOAD, Horloge, P, releve_gk5


class Monde:
    def __init__(self, tmp_path, jwt=True, delai=0.3):
        self.h = Horloge()
        self.s = StockageSqlite(tmp_path / "p", horloge=self.h)
        self.f = Files()
        self.lignes = []
        self.audit_ko = False
        self.inv = Inventaire(self.f, self.s, horloge=self.h)
        self.app = creer_app_admin(self.s, self.f, self.inv, self.audit, horloge=self.h, delai_lecture_s=delai)
        if jwt:
            self.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "alice"}

    def audit(self, evenement, champs):
        if self.audit_ko:
            raise OSError("disque plein")
        self.lignes.append((evenement, champs))

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://t")


@pytest.fixture
def m(tmp_path):
    return Monde(tmp_path)


def test_boxes_exige_un_jwt(tmp_path):
    m = Monde(tmp_path, jwt=False)
    c = TestClient(m.app)
    for methode, url in (("get", "/boxes"), ("get", "/boxes/gk5"), ("get", "/boxes/gk5/lire?chemin=Device."), ("post", "/boxes/gk5/releve"),
                         ("get", "/boxes/gk5/releve"), ("get", "/evenements")):
        assert getattr(c, methode)(url).status_code == 401, url


def test_boxes_resume_l_inventaire(m):
    m.s.vu(GK5, {"agent_version": "0.1.0"})
    m.s.inventaire_enregistrer(GK5, releve_gk5())
    (b,) = TestClient(m.app).get("/boxes").json()
    assert b["nom"] == "gk5" and b["cle"] == "maillage:gk5" and b["en_ligne"] is True
    assert b["swap_utilise_pct"] == 66 and b["services_en_echec"] == 0 and b["mains_liees"] is False
    assert b["memoire_dispo_mo"] == 512 and b["agent_version"] == "0.1.0"
    d = TestClient(m.app).get("/boxes/gk5").json()
    assert d["inventaire"][P + "X_SECUBOX_Services.1.Name"] == "secubox-hub.service" and d["inventaire_partiel"] is False


def test_hors_ligne_apres_90_s(m):
    m.s.vu(GK5, {})
    c = TestClient(m.app)
    m.h.avance(91)
    assert c.get("/boxes").json()[0]["en_ligne"] is False
    assert c.get("/boxes/gk5").json()["en_ligne"] is False


def test_designation_par_cle_ou_nom_unique(m):
    m.s.vu(GK5, {})
    m.s.vu(GK5_AUTOLOAD, {})
    m.s.vu(GK2, {})
    c = TestClient(m.app)
    r = c.get("/boxes/gk5")
    assert r.status_code == 409 and sorted(r.json()["detail"]["cles"]) == ["autoload:gk5", "maillage:gk5"]
    assert c.get("/boxes/autoload:gk5").json()["adresse"] == "10.64.0.9"
    assert c.get("/boxes/gk2").json()["cle"] == "maillage:gk2"
    assert c.get("/boxes/inconnue").status_code == 404


@pytest.mark.asyncio
async def test_lire_en_direct(m):
    m.s.vu(GK5, {})
    async with m.client() as c:
        t = asyncio.create_task(c.get("/boxes/gk5/lire", params={"chemin": P + "DeviceInfo.UpTime"}))
        (rq,) = await m.f.attendre_requetes(GK5.cle, 2)
        assert rq["type"] == "GET" and rq["body"] == {"paths": [P + "DeviceInfo.UpTime"]}
        m.f.livrer_reponse(GK5.cle, {"msg_id": rq["msg_id"], "type": "GET_RESP",
                                     "body": {"results": [{"path": P + "DeviceInfo.UpTime", "params": {P + "DeviceInfo.UpTime": 42}}]}})
        r = await t
    assert r.status_code == 200 and r.json()["results"][0]["params"][P + "DeviceInfo.UpTime"] == 42 and r.json()["tronque"] is False


@pytest.mark.asyncio
async def test_lire_en_direct_et_delai(m):
    m.s.vu(GK5, {})
    async with m.client() as c:
        t0 = time.monotonic()
        r = await c.get("/boxes/gk5/lire", params={"chemin": "Device."})  # agent factice : ne répond pas
    assert r.status_code == 504 and time.monotonic() - t0 < 16
    assert m.f.en_attente(GK5.cle) == 0  # la requête abandonnée ne reste pas en file


def test_delai_de_lecture_par_defaut_est_15_s(tmp_path):
    from api.main import DELAI_LECTURE_S
    assert DELAI_LECTURE_S == 15.0


def test_lire_valide_le_chemin_et_l_etat_de_la_box(m):
    m.s.vu(GK5, {})
    c = TestClient(m.app)
    for chemin in ("", "Autre.chose", "Device.\x00", "Device.a b", "Device.a;b", "Device.Reboot()", "Device." + "a" * 300, "Device.é"):
        assert c.get("/boxes/gk5/lire", params={"chemin": chemin}).status_code == 422, repr(chemin)
    assert c.get("/boxes/nope/lire", params={"chemin": "Device."}).status_code == 404
    m.h.avance(91)
    assert c.get("/boxes/gk5/lire", params={"chemin": "Device."}).status_code == 409  # immédiat, sans dépôt
    assert m.f.en_attente(GK5.cle) == 0


@pytest.mark.asyncio
async def test_lire_erreur_de_la_box_est_un_502(m):
    m.s.vu(GK5, {})
    async with m.client() as c:
        t = asyncio.create_task(c.get("/boxes/gk5/lire", params={"chemin": "Device."}))
        (rq,) = await m.f.attendre_requetes(GK5.cle, 2)
        m.f.livrer_reponse(GK5.cle, {"msg_id": rq["msg_id"], "type": "ERROR", "body": {"err": "chemin invalide"}})
        r = await t
    assert r.status_code == 502


@pytest.mark.asyncio
async def test_releve_audite_et_range(m):
    m.s.vu(GK5, {})
    async with m.client() as c:
        r = await c.post("/boxes/gk5/releve", json={"duree_s": 30})
        assert r.status_code == 202 and r.json()["duree_s"] == 30
        assert m.lignes == [("pilotage_releve_demande", {"cle": "maillage:gk5", "acteur": "alice", "duree_s": 30})]
        (rq,) = await m.f.attendre_requetes(GK5.cle, 2)
        assert rq["type"] == "OPERATE" and rq["body"] == {"command": "Device.X_SECUBOX_Releve.Mesurer()", "args": {"duree_s": 30}}
        # un second relevé pendant le premier : refusé
        assert (await c.post("/boxes/gk5/releve", json={})).status_code == 409
        assert (await c.get("/boxes/gk5/releve")).json() == {"cle": "maillage:gk5", "en_cours": True, "releve": None}
        m.f.livrer_reponse(GK5.cle, {"msg_id": rq["msg_id"], "type": "OPERATE_RESP", "body": {"output": {"processus": [{"comm": "x"}]}}})
        await asyncio.sleep(0.2)
        j = (await c.get("/boxes/gk5/releve")).json()
    assert j["en_cours"] is False and j["releve"]["statut"] == "ok" and j["releve"]["sortie"] == {"processus": [{"comm": "x"}]}
    assert "processus" not in json.dumps(m.lignes)  # aucune valeur dans l'audit


def test_releve_duree_valide(m):
    m.s.vu(GK5, {})
    c = TestClient(m.app)
    for corps in ({"duree_s": 9}, {"duree_s": 301}, {"duree_s": 60.5}, {"duree_s": 60.0}, {"duree_s": "60"}, {"duree_s": True},
                  {"duree_s": None}, {"autre": 1}):
        assert c.post("/boxes/gk5/releve", json=corps).status_code == 422, corps
    assert c.post("/boxes/gk5/releve", content='{"duree_s": NaN}', headers={"content-type": "application/json"}).status_code == 422
    assert m.lignes == [] and m.f.en_attente(GK5.cle) == 0
    assert c.post("/boxes/gk5/releve", json={"duree_s": 10}).status_code == 202
    assert c.post("/boxes/gk2/releve", json={}).status_code == 404


def test_releve_hors_ligne_et_audit_en_panne(m):
    m.s.vu(GK5, {})
    c = TestClient(m.app)
    m.audit_ko = True
    r = c.post("/boxes/gk5/releve", json={})
    assert r.status_code == 503 and m.f.en_attente(GK5.cle) == 0   # pas d'audit, pas de relevé
    m.audit_ko = False
    assert c.post("/boxes/gk5/releve", json={}).status_code == 202   # la réservation a été relâchée
    m.h.avance(91)
    assert c.post("/boxes/gk5/releve", json={}).status_code == 409


def test_evenements_filtres(m):
    m.s.vu(GK5, {})
    m.s.vu(GK2, {})
    m.s.notification(GK5, {"type": "X_SECUBOX_ServiceLoop", "unit": "a.service", "value": 7, "ts": 5})
    m.h.avance(100)
    m.s.notification(GK2, {"type": "X_SECUBOX_Boot", "value": 3, "ts": 6})
    c = TestClient(m.app)
    assert [e["type"] for e in c.get("/evenements").json()] == ["X_SECUBOX_Boot", "X_SECUBOX_ServiceLoop"]
    (e,) = c.get("/evenements", params={"nom": "gk5"}).json()
    assert e["nom"] == "gk5" and e["unite"] == "a.service" and e["valeur"] == 7 and e["survenu_le"] == 5
    assert [e["nom"] for e in c.get("/evenements", params={"depuis": int(m.h.t) - 50}).json()] == ["gk2"]
    assert c.get("/evenements", params={"nom": "x"}).status_code == 404
    assert c.get("/evenements", params={"depuis": -1}).status_code == 422


def test_construire_assemble_deux_applications(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_PILOTAGE_DOSSIER", str(tmp_path / "d"))
    monkeypatch.setenv("SECUBOX_PILOTAGE_AUDIT", str(tmp_path / "audit.log"))
    from api.asgi import construire
    admin, canal = construire()
    assert {r.path for r in admin.routes} >= {"/boxes", "/boxes/{ident}", "/evenements"}
    assert any(r.path == "/canal/v1/bonjour" for r in canal.routes) and not any(r.path == "/boxes" for r in canal.routes)
    assert all("/canal/" not in r.path for r in admin.routes)
    # le service n'est pas exposé en lecture libre : chaque route d'administration a la garde
    for r in admin.routes:
        if getattr(r, "dependant", None) and r.path.startswith(("/boxes", "/evenements")):
            assert any(d.call is auth.require_jwt for d in r.dependant.dependencies), r.path


def test_audit_journal_append_only(tmp_path):
    from pilotage.audit import journal
    a = journal(tmp_path / "audit.log")
    a("pilotage_releve_demande", {"cle": "maillage:gk5", "acteur": "alice"})
    a("pilotage_releve_demande", {"cle": "maillage:gk2", "acteur": "bob", "action": "usurpe"})
    lignes = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    assert [x["cle"] for x in lignes] == ["maillage:gk5", "maillage:gk2"] and lignes[1]["action"] == "pilotage_releve_demande"
    assert lignes[0]["module"] == "pilotage"
