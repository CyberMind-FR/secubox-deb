# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2 tâche 6 — actions sur le contrôleur : API d'administration, confirmation forte, consentement renvoyé tel quel,
support borné à 240 min et réservé à une session ouverte, audit maître, suivi des fins et Rejoindre après un renommage."""
import asyncio
import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from secubox_core import auth

from api.main import creer_app_admin
from pilotage.files import Files
from pilotage.inventaire import Inventaire
from pilotage.operations import Suivi
from pilotage.stockage import StockageSqlite
from outils import GK2, GK5, GK5_AUTOLOAD, Horloge
from test_renommage import code_maillage

CODE = code_maillage()


class Monde:
    def __init__(self, tmp_path, jwt=True, sub="alice", emettre=None, noms=()):
        self.h = Horloge()
        self.s = StockageSqlite(tmp_path / "p", horloge=self.h)
        self.f = Files()
        self.lignes = []
        self.audit_ko = False
        self.emis = []
        self.inv = Inventaire(self.f, self.s, horloge=self.h)
        self.suivi = Suivi(self.s, self.f, self.audit, emettre=emettre or self.emettre)
        self.app = creer_app_admin(self.s, self.f, self.inv, self.audit, horloge=self.h, delai_lecture_s=0.3, suivi=self.suivi,
                                   noms_pris=lambda: set(noms), delai_action_s=0.5)
        if jwt:
            self.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": sub}

    def emettre(self, nom):
        self.emis.append(nom)
        return CODE

    def audit(self, evenement, champs):
        if self.audit_ko:
            raise OSError("disque plein")
        self.lignes.append((evenement, dict(champs)))

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://t")

    async def repondre(self, box, corps, type_="OPERATE_RESP"):
        """L'agent prend la requête suivante et y répond ; rend la requête."""
        (rq,) = await self.f.attendre_requetes(box.cle, 2)
        self.f.livrer_reponse(box.cle, {"msg_id": rq["msg_id"], "type": type_, "body": corps})
        return rq


@pytest.fixture
def m(tmp_path):
    w = Monde(tmp_path)
    w.s.vu(GK5, {})
    return w


ACCEPTE = {"etat": "accepte", "job": "a1b2c3d4e5f60718", "raison": ""}


def test_routes_d_action_exigent_un_jwt(tmp_path):
    w = Monde(tmp_path, jwt=False)
    c = TestClient(w.app)
    for methode, url in (("post", "/boxes/gk5/actions/reboot"), ("get", "/operations"), ("post", "/boxes/gk5/support"),
                         ("get", "/boxes/gk5/support"), ("delete", "/boxes/gk5/support/s1")):
        assert c.request(methode, url, json={}).status_code == 401, url
    for r in w.app.routes:
        if getattr(r, "dependant", None) and r.path.startswith(("/boxes", "/operations")):
            assert any(d.call is auth.require_jwt for d in r.dependant.dependencies), r.path


@pytest.mark.parametrize("action,args", [("reboot", {}), ("service-arreter", {"unite": "secubox-hub.service"}), ("renouveler", {}),
                                         ("renommer", {"nom": "gk9"})])
def test_confirmation_forte_exigee_sur_une_box_du_proprietaire(m, action, args):
    c = TestClient(m.app)
    for confirmation in (None, "", "GK5", "gk5 ", "gk2", "maillage:gk5"):
        corps = {"args": args} if confirmation is None else {"args": args, "confirmation": confirmation}
        assert c.post(f"/boxes/gk5/actions/{action}", json=corps).status_code == 400, confirmation
    assert m.lignes == [] and m.f.en_attente(GK5.cle) == 0          # rien d'audité, rien d'envoyé


@pytest.mark.asyncio
async def test_action_acceptee_auditee_et_rangee(m):
    async with m.client() as c:
        t = asyncio.create_task(c.post("/boxes/gk5/actions/reboot", json={"confirmation": "gk5"}))
        rq = await m.repondre(GK5, ACCEPTE)
        r = await t
    assert rq["type"] == "OPERATE" and rq["body"] == {"command": "Device.Reboot()", "args": {}, "acteur": "alice"}
    j = r.json()
    assert r.status_code == 200 and j["etat"] == "accepte" and j["job"] == "a1b2c3d4e5f60718" and j["action"] == "reboot"
    assert [(e, c.get("etat"), c.get("job")) for e, c in m.lignes] == [("pilotage_action", "demande", None),
                                                                       ("pilotage_action", "accepte", "a1b2c3d4e5f60718")]
    assert m.lignes[1][1] == {"box": "gk5", "cle": "maillage:gk5", "action": "reboot", "acteur": "alice", "args": "{}",
                              "job": "a1b2c3d4e5f60718", "etat": "accepte", "operation": j["operation"]}
    (o,) = TestClient(m.app).get("/operations", params={"nom": "gk5"}).json()
    assert o["id"] == j["operation"] and o["etat"] == "accepte" and o["acteur"] == "alice" and o["nom"] == "gk5"


def ouvrir_support(m, box, sid="s1", duree_min=30):
    """Session de support demandée par le maître puis acceptée sur la box (notification « ouvert »)."""
    m.s.support_demander(box.cle, sid, duree_min, "alice")
    assert m.s.support_noter(box.cle, sid, "ouvert", None)


def test_box_cliente_action_seulement_pendant_un_support(tmp_path):
    """I3 (R-L2-47) : le catalogue d'une box cliente n'est servi que pendant une session de support ouverte et non échue de
    CETTE box, appliqué par le serveur (la page seule ne suffit pas) : sinon 409, rien d'audité ni d'envoyé."""
    m = Monde(tmp_path)
    m.s.vu(GK5_AUTOLOAD, {})
    m.s.vu(GK2, {})
    c = TestClient(m.app)
    url = "/boxes/autoload:gk5/actions/maj-paquets"
    assert c.post(url, json={}).status_code == 409                                 # sans support
    m.s.support_demander(GK5_AUTOLOAD.cle, "s1", 30, "alice")
    assert c.post(url, json={"support": "s1"}).status_code == 409                  # demandé, pas accepté
    ouvrir_support(m, GK2, "s2")
    assert c.post(url, json={"support": "s2"}).status_code == 409                  # session d'une autre box
    assert m.s.support_noter(GK5_AUTOLOAD.cle, "s1", "ouvert", None)
    m.h.avance(31 * 60)
    assert c.post(url, json={"support": "s1"}).status_code == 409                  # échue
    assert m.lignes == [] and m.f.en_attente(GK5_AUTOLOAD.cle) == 0 and m.s.operations(GK5_AUTOLOAD.cle) == []


@pytest.mark.asyncio
async def test_box_cliente_consentement_renvoye_tel_quel(tmp_path):
    m = Monde(tmp_path)
    m.s.vu(GK5_AUTOLOAD, {})
    ouvrir_support(m, GK5_AUTOLOAD)
    rep = {"etat": "consentement", "job": "", "raison": "consentement requis : accord du détenteur"}
    async with m.client() as c:
        # box cliente : la confirmation forte n'est pas exigée (l'accord du détenteur la remplace)
        t = asyncio.create_task(c.post("/boxes/autoload:gk5/actions/reboot", json={"support": "s1"}))
        await m.repondre(GK5_AUTOLOAD, rep)
        r = await t
    j = r.json()
    assert r.status_code == 200 and {k: j[k] for k in ("etat", "job", "raison")} == rep
    (o,) = m.s.operations(GK5_AUTOLOAD.cle)
    assert o["etat"] == "consentement" and o["job"] is None


@pytest.mark.asyncio
async def test_service_et_maj_sans_confirmation(m):
    async with m.client() as c:
        t = asyncio.create_task(c.post("/boxes/gk5/actions/service-redemarrer", json={"args": {"unite": "secubox-hub.service"}}))
        rq = await m.repondre(GK5, ACCEPTE)
        assert (await t).status_code == 200
        assert rq["body"]["command"] == "Device.X_SECUBOX_Services.Agir()"
        assert rq["body"]["args"] == {"unite": "secubox-hub.service", "action": "redemarrer"}
        # M3 : les paramètres validés (jamais secrets) sont audités
        assert json.loads(m.lignes[0][1]["args"]) == {"unite": "secubox-hub.service", "action": "redemarrer"}
        t = asyncio.create_task(c.post("/boxes/gk5/actions/maj-paquets", json={}))
        rq = await m.repondre(GK5, {**ACCEPTE, "job": "b1"})
        assert (await t).status_code == 200 and rq["body"]["command"] == "Device.X_SECUBOX_Packages.MettreAJour()"


def test_arguments_et_actions_valides(m):
    c = TestClient(m.app)
    assert c.post("/boxes/gk5/actions/shell", json={}).status_code == 404
    for action, corps in (("service-demarrer", {"args": {}}), ("service-demarrer", {"args": {"unite": "nginx.service"}}),
                          ("service-demarrer", {"args": {"unite": "secubox-hub.service", "x": 1}}),
                          ("service-demarrer", {"args": {"unite": "secubox-hub.service; reboot"}}),
                          ("maj-paquets", {"args": {"x": 1}}), ("maj-paquets", {"autre": 1}),
                          ("renommer", {"args": {"nom": "GK9"}, "confirmation": "gk5"}),
                          ("renommer", {"args": {"nom": "-gk9"}, "confirmation": "gk5"}),
                          ("renommer", {"args": {}, "confirmation": "gk5"}),
                          ("maj-paquets", {"support": "../x"})):
        assert c.post(f"/boxes/gk5/actions/{action}", json=corps).status_code == 422, (action, corps)
    assert m.lignes == [] and m.f.en_attente(GK5.cle) == 0


def test_renommer_vers_un_nom_deja_pris_au_maillage(tmp_path):
    m = Monde(tmp_path, noms={"maitre"})
    m.s.vu(GK5, {})
    m.s.vu(GK2, {})
    c = TestClient(m.app)
    for nom in ("gk2", "gk5", "maitre"):
        r = c.post("/boxes/gk5/actions/renommer", json={"args": {"nom": nom}, "confirmation": "gk5"})
        assert r.status_code == 409, nom
    assert m.lignes == [] and m.f.en_attente(GK5.cle) == 0


def test_hors_ligne_audit_en_panne_et_sans_reponse(m):
    c = TestClient(m.app)
    m.audit_ko = True
    assert c.post("/boxes/gk5/actions/maj-paquets", json={}).status_code == 503
    assert m.f.en_attente(GK5.cle) == 0 and m.s.operations(GK5.cle) == []
    m.audit_ko = False
    r = c.post("/boxes/gk5/actions/maj-paquets", json={})     # l'agent factice ne répond pas
    assert r.status_code == 504
    (o,) = m.s.operations(GK5.cle)
    assert o["etat"] == "sans_reponse" and m.lignes[-1][1]["etat"] == "sans_reponse"
    m.h.avance(91)
    assert c.post("/boxes/gk5/actions/maj-paquets", json={}).status_code == 409


@pytest.mark.asyncio
async def test_acteur_hors_motif_non_transmis_mais_audite(tmp_path):
    m = Monde(tmp_path, sub="Alice Dupont")
    m.s.vu(GK5, {})
    async with m.client() as c:
        t = asyncio.create_task(c.post("/boxes/gk5/actions/maj-paquets", json={}))
        rq = await m.repondre(GK5, ACCEPTE)
        await t
    assert "acteur" not in rq["body"] and m.lignes[0][1]["acteur"] == "Alice Dupont"


@pytest.mark.asyncio
async def test_erreur_de_l_agent_rangee_comme_refus(m):
    async with m.client() as c:
        t = asyncio.create_task(c.post("/boxes/gk5/actions/maj-paquets", json={}))
        await m.repondre(GK5, {"err": "lecture seule"}, type_="ERROR")
        j = (await t).json()
    assert j["etat"] == "refuse" and j["raison"] == "lecture seule" and m.s.operations(GK5.cle)[0]["etat"] == "refuse"


# --- support ---

def test_support_borne_a_240_min(m):
    c = TestClient(m.app)
    for corps in ({"duree_min": 0}, {"duree_min": 241}, {"duree_min": 30.0}, {"duree_min": "30"}, {"duree_min": True}, {"x": 1}):
        assert c.post("/boxes/gk5/support", json=corps).status_code == 422, corps
    assert m.lignes == [] and m.f.en_attente(GK5.cle) == 0


@pytest.mark.asyncio
async def test_support_demande_auditee_et_consentement_tel_quel(m):
    rep = {"etat": "consentement", "job": "", "raison": "accord du détenteur requis"}
    async with m.client() as c:
        t = asyncio.create_task(c.post("/boxes/gk5/support", json={}))
        rq = await m.repondre(GK5, rep)
        r = await t
        t = asyncio.create_task(c.post("/boxes/gk5/support", json={"duree_min": 240}))
        rq2 = await m.repondre(GK5, rep)
        await t
    j = r.json()
    assert r.status_code == 200 and {k: j[k] for k in ("etat", "job", "raison")} == rep
    assert rq["body"] == {"command": "Device.X_SECUBOX_Support.Ouvrir()", "args": {"id": j["id"], "duree_min": 30}, "acteur": "alice"}
    assert rq2["body"]["args"]["duree_min"] == 240
    assert m.lignes[0] == ("pilotage_support", {"box": "gk5", "cle": "maillage:gk5", "acteur": "alice", "id": j["id"], "duree_min": 30,
                                                "etat": "demande"})
    (s, _) = sorted(m.s.supports(GK5.cle), key=lambda x: x["id"] != j["id"])
    assert s["id"] == j["id"] and s["etat"] == "demande" and s["duree_min"] == 30


@pytest.mark.asyncio
async def test_action_de_support_reservee_a_une_session_ouverte(m):
    """R-L2-31 : une action demandée DANS le cadre d'un support porte l'identifiant de la session ; le maître la refuse tant
    que la session n'est pas ouverte sur la box, et dès qu'elle a passé sa fin (même sans notification de fermeture)."""
    m.s.support_demander(GK5.cle, "s1", 30, "alice")
    c = TestClient(m.app)
    assert c.post("/boxes/gk5/actions/maj-paquets", json={"support": "s1"}).status_code == 409   # pas encore acceptée
    m.s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "s1", "etat": "ouvert", "ts": 1})
    assert c.post("/boxes/gk5/actions/maj-paquets", json={"support": "s9"}).status_code == 409   # autre session
    async with m.client() as ac:
        t = asyncio.create_task(ac.post("/boxes/gk5/actions/maj-paquets", json={"support": "s1"}))
        await m.repondre(GK5, ACCEPTE)
        assert (await t).status_code == 200
    assert m.s.operations(GK5.cle)[0]["support"] == "s1" and m.lignes[-1][1]["support"] == "s1"
    m.h.avance(30 * 60 + 1)
    assert c.post("/boxes/gk5/actions/maj-paquets", json={"support": "s1"}).status_code == 409   # échue : le maître expire seul
    assert c.get("/boxes/gk5/support").json()[0]["etat"] == "expire"


@pytest.mark.asyncio
async def test_fermer_le_support(m):
    m.s.support_demander(GK5.cle, "s1", 30, "alice")
    m.s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "s1", "etat": "ouvert", "ts": 1})
    async with m.client() as c:
        assert (await c.delete("/boxes/gk5/support/inconnue")).status_code == 404
        assert (await c.delete("/boxes/gk5/support/A..B")).status_code == 422
        t = asyncio.create_task(c.delete("/boxes/gk5/support/s1"))
        rq = await m.repondre(GK5, {"etat": "accepte", "job": "", "raison": ""})
        r = await t
    assert r.status_code == 200 and r.json()["etat"] == "accepte"
    assert rq["body"] == {"command": "Device.X_SECUBOX_Support.Fermer()", "args": {"id": "s1"}, "acteur": "alice"}
    assert m.s.support_ouvert(GK5.cle, "s1") is None                    # fermée côté maître tout de suite
    assert ("pilotage_support_fermeture", {"box": "gk5", "cle": "maillage:gk5", "acteur": "alice", "id": "s1"}) in m.lignes


def test_fermer_le_support_d_une_box_hors_ligne(m):
    m.s.support_demander(GK5.cle, "s1", 30, "alice")
    m.s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "s1", "etat": "ouvert", "ts": 1})
    m.h.avance(91)
    r = TestClient(m.app).delete("/boxes/gk5/support/s1")
    assert r.status_code == 200 and r.json()["etat"] == "hors_ligne" and m.s.support_ouvert(GK5.cle, "s1") is None


# --- suivi des fins et Rejoindre (R-L2-35) ---

async def lancer(m, c, box, action, corps, job):
    t = asyncio.create_task(c.post(f"/boxes/{box.cle}/actions/{action}", json=corps))
    await m.repondre(box, {"etat": "accepte", "job": job, "raison": ""})
    return (await t).json()


@pytest.mark.asyncio
async def test_fin_auditee_une_fois(m):
    async with m.client() as c:
        await lancer(m, c, GK5, "maj-paquets", {}, "j1")
    done = {"type": "X_SECUBOX_OperationDone", "job": "j1", "rc": 100, "resume": "maj-paquets : échec (code 100)", "ts": 3}
    for _ in range(2):
        op = m.s.notification(GK5, done)
        if op is not None:
            await m.suivi.apres_fin(GK5, op)
    res = [c for e, c in m.lignes if e == "pilotage_action_resultat"]
    assert res == [{"box": "gk5", "cle": "maillage:gk5", "action": "maj-paquets", "job": "j1", "rc": 100, "resultat": "echec"}]


async def fin(m, box, job, rc=0):
    op = await asyncio.to_thread(m.s.notification, box, {"type": "X_SECUBOX_OperationDone", "job": job, "rc": rc, "ts": 9})
    if op is not None:
        await m.suivi.apres_fin(box, op)


@pytest.mark.asyncio
async def test_renommage_reussi_envoie_rejoindre_sans_jamais_ecrire_le_code(m, caplog, tmp_path):
    caplog.set_level(logging.DEBUG)
    async with m.client() as c:
        await lancer(m, c, GK5, "renommer", {"args": {"nom": "gk9"}, "confirmation": "gk5"}, "j1")
        await fin(m, GK5, "j1")
        rq = await m.repondre(GK5, {"etat": "accepte", "job": "", "raison": ""})
        await fin(m, GK5, "j1")                                                    # renotification : rien de plus
        await m.suivi.attendre()
    assert m.emis == ["gk9"]
    assert rq["body"]["command"] == "Device.X_SECUBOX_Maillage.Rejoindre()" and rq["body"]["args"] == {"code": CODE}
    assert m.f.en_attente(GK5.cle) == 0
    evs = [e for e, _ in m.lignes]
    assert evs.count("pilotage_rejoindre_envoye") == 1 and "pilotage_rejoindre_resultat" in evs
    assert CODE not in json.dumps(m.lignes) and CODE not in caplog.text
    for f in (tmp_path / "p").iterdir():                                           # ni dans la base, ni dans son journal WAL
        assert CODE.encode() not in f.read_bytes(), f


@pytest.mark.asyncio
async def test_fin_avant_la_reponse_rejoindre_quand_meme(m):
    async with m.client() as c:
        t = asyncio.create_task(c.post("/boxes/gk5/actions/renommer", json={"args": {"nom": "gk9"}, "confirmation": "gk5"}))
        (rq,) = await m.f.attendre_requetes(GK5.cle, 2)
        await fin(m, GK5, "j1")                                                    # la fin arrive avant l'OPERATE_RESP
        m.f.livrer_reponse(GK5.cle, {"msg_id": rq["msg_id"], "type": "OPERATE_RESP", "body": {"etat": "accepte", "job": "j1", "raison": ""}})
        j = (await t).json()
        rj = await m.repondre(GK5, {"etat": "accepte", "job": "", "raison": ""})
        await m.suivi.attendre()
    assert j["etat"] == "accepte" and j["operation_etat"] == "termine" and m.emis == ["gk9"] and rj["body"]["command"] == "Device.X_SECUBOX_Maillage.Rejoindre()"
    # I1 : la fin orpheline n'est pas auditée à sa réception (action inconnue), mais une fois, à la fusion, avec son action
    res = [c for e, c in m.lignes if e == "pilotage_action_resultat"]
    assert res == [{"box": "gk5", "cle": "maillage:gk5", "action": "renommer", "job": "j1", "rc": 0, "resultat": "succes"}]
    (o,) = m.s.operations(GK5.cle)
    assert o["action"] == "renommer" and o["resultat"] == "succes"


@pytest.mark.asyncio
async def test_pas_de_rejoindre_pour_une_box_cliente_ni_un_echec(tmp_path):
    m = Monde(tmp_path)
    m.s.vu(GK5_AUTOLOAD, {})
    m.s.vu(GK5, {})
    ouvrir_support(m, GK5_AUTOLOAD)
    async with m.client() as c:
        await lancer(m, c, GK5_AUTOLOAD, "renommer", {"args": {"nom": "gk9"}, "support": "s1"}, "j1")
        await fin(m, GK5_AUTOLOAD, "j1")
        await lancer(m, c, GK5, "renommer", {"args": {"nom": "gk8"}, "confirmation": "gk5"}, "j2")
        await fin(m, GK5, "j2", rc=1)
        await m.suivi.attendre()
    assert m.emis == [] and m.f.en_attente(GK5.cle) == 0 and m.f.en_attente(GK5_AUTOLOAD.cle) == 0


@pytest.mark.asyncio
async def test_emission_du_code_en_echec_auditee_sans_code(tmp_path):
    from pilotage.renommage import ErreurRejoindre

    def panne(nom):
        raise ErreurRejoindre("sbx-mesh-invite en échec (code 1)")

    m = Monde(tmp_path, emettre=panne)
    m.s.vu(GK5, {})
    async with m.client() as c:
        await lancer(m, c, GK5, "renommer", {"args": {"nom": "gk9"}, "confirmation": "gk5"}, "j1")
        await fin(m, GK5, "j1")
        await m.suivi.attendre()
    (e,) = [c for ev, c in m.lignes if ev == "pilotage_rejoindre_echec"]
    assert e == {"box": "gk5", "cle": "maillage:gk5", "nouveau": "gk9", "raison": "sbx-mesh-invite en échec (code 1)"}
    assert m.f.en_attente(GK5.cle) == 0


def test_resultat_inconnu_affiche(m):
    op = m.s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
    m.s.operation_reponse(op, "accepte", "j1", "")
    m.s.operation_fin(GK5.cle, "j1", -1, "maj-paquets : résultat inconnu")
    (o,) = TestClient(m.app).get("/operations").json()
    assert o["resultat"] == "inconnu" and o["resume"] == "maj-paquets : résultat inconnu"
    assert TestClient(m.app).get("/operations", params={"nom": "inconnue"}).status_code == 404


@pytest.mark.asyncio
async def test_file_pleine_429_et_operation_jamais_laissee_en_demande(m):
    for _ in range(m.f.max_par_box):
        m.f.deposer(GK5.cle, {"type": "GET", "body": {"paths": ["Device."]}})
    async with m.client() as c:
        assert (await c.post("/boxes/gk5/actions/maj-paquets", json={})).status_code == 429
    (o,) = m.s.operations(GK5.cle)
    assert o["etat"] == "refuse" and o["raison"] == "file de la box pleine"
    assert m.lignes[-1][1]["etat"] == "refuse"



@pytest.mark.asyncio
async def test_mille_fins_inventees_ni_audit_ni_eviction(m, caplog):
    """I1 : une box qui invente des jobs ne gonfle pas l'audit du maître et n'évince pas l'historique réel."""
    caplog.set_level(logging.INFO, logger="pilotage.operations")
    vraie = m.s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
    m.s.operation_reponse(vraie, "accepte", "vrai", "")
    for i in range(1000):
        op = m.s.notification(GK5, {"type": "X_SECUBOX_OperationDone", "job": f"x{i}", "rc": 0, "ts": 1})
        if op is not None:
            await m.suivi.apres_fin(GK5, op)
    assert [e for e, _ in m.lignes if e == "pilotage_action_resultat"] == []
    ops = m.s.operations(GK5.cle, 1000)
    assert vraie in [o["id"] for o in ops] and len([o for o in ops if o["action"] is None]) <= 100
    lignes = [r for r in caplog.records if "non rattachée" in r.getMessage()]
    assert len(lignes) <= 1                                   # une ligne agrégée par box et par minute au plus


@pytest.mark.asyncio
async def test_support_sans_reponse_apres_504(m):
    async with m.client() as c:
        r = await c.post("/boxes/gk5/support", json={})
    assert r.status_code == 504
    (s,) = m.s.supports(GK5.cle)
    assert s["etat"] == "sans_reponse"


def test_le_maitre_attend_l_agent_plus_longtemps_que_l_agent_n_attend_le_ctl():
    """Mineur de la relecture finale (R-L2-47) : le maître (90 s) attend l'OPERATE_RESP plus longtemps que l'agent n'attend le
    ctl (60 s, sbx-pilotage-agent : delaiCtl), sinon une action lancée sur la box serait rendue « sans réponse » au maître. La
    réponse servie reste attendue par la file plus longtemps encore."""
    import re
    from pathlib import Path

    import api.main as api_main
    from pilotage.files import EXPIRATION_REPONSE_S

    go = (Path(__file__).resolve().parents[2] / "secubox-pilotage-agent" / "cmd" / "sbx-pilotage-agent" / "ancre.go").read_text()
    (agent_s,) = [int(x) for x in re.findall(r"delaiCtl\s*=\s*(\d+)\s*\*\s*time\.Second", go)]
    assert agent_s == 60
    assert api_main.DELAI_ACTION_S == 90.0
    assert agent_s < api_main.DELAI_ACTION_S < EXPIRATION_REPONSE_S


# ── #3338 : installer une app de la boutique sur une box du parc ─────────────────────────────────────────────────────

def test_installer_valide_le_paquet(m):
    from pilotage.operations import CATALOGUE, arguments
    a = CATALOGUE["installer"]
    assert a.commande == "Device.X_SECUBOX_Packages.Installer()" and a.forte
    assert arguments(a, {"paquet": "secubox-jellyfin"}) == {"paquet": "secubox-jellyfin"}
    for mauvais in ({}, {"paquet": "nginx"}, {"paquet": "secubox-Jelly"}, {"paquet": "secubox-a;reboot"},
                    {"paquet": "secubox-" + "a" * 49}, {"paquet": "secubox-x", "version": "1"}):
        assert arguments(a, mauvais) is None, mauvais
    c = TestClient(m.app)
    assert c.post("/boxes/gk5/actions/installer", json={"args": {"paquet": "nginx"}, "confirmation": "gk5"}).status_code == 422
    assert c.post("/boxes/gk5/actions/installer", json={"args": {"paquet": "secubox-jellyfin"}}).status_code == 400
    assert m.lignes == [] and m.f.en_attente(GK5.cle) == 0
