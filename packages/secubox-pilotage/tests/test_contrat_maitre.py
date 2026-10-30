# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contrat maître → agent (#3126, N5 / M14 de la relecture finale L1, R-L2-38).

Sens maître → agent : chaque requête que le maître dépose pour une box est produite ici par le VRAI contrôleur (routes de l'API
d'administration, tour d'inventaire, suite d'un renommage), capturée dans la file de la box et comparée octet à octet à sa fixture,
versionnée dans `secubox-pilotage-agent/internal/canal/testdata/contrat/maitre/`. Le test Go `TestContratRequetesDuMaitre`
(cmd/sbx-pilotage-agent) les rejoue contre le vrai client de l'agent et son vrai exécuteur, et vérifie ce que l'agent en fait
(argv du ctl, type de réponse). Il fige à son tour, dans `.../contrat/agent-l2/`, les réponses et notifications de L2 qu'il émet ;
le second volet de ce fichier les rejoue contre le vrai canal, le vrai stockage et les vraies routes qui les consomment.

Régénération (après un changement voulu de ce que le maître émet), puis le test Go, puis ce fichier :

    SECUBOX_CONTRAT_MAJ=1 python -m pytest tests/test_contrat_maitre.py -k figees
    SECUBOX_CONTRAT_MAJ=1 go test ./cmd/sbx-pilotage-agent -run TestContratRequetesDuMaitre

Aucun code de jonction réel : Rejoindre porte un code factice au bon format (somme de contrôle juste, jeton « fa… »).
"""
import asyncio
import base64
import hashlib
import json
import os
import types
from pathlib import Path

import httpx
import pytest

from secubox_core import auth

import api.main as api_main
from api.main import creer_app_admin
from pilotage.files import Files, requete_modele
from pilotage.inventaire import Inventaire
from pilotage.operations import Suivi
from pilotage.stockage import TYPE_FIN, StockageSqlite
from outils import GK5, Horloge

CONTRAT = Path(__file__).resolve().parents[2] / "secubox-pilotage-agent" / "internal" / "canal" / "testdata" / "contrat"
MAITRE = CONTRAT / "maitre"
AGENT_L2 = CONTRAT / "agent-l2"
MAJ = os.environ.get("SECUBOX_CONTRAT_MAJ") == "1"
SUPPORT_ID = "5e55105000000001"   # identifiant de session de support figé (le maître le tire au hasard : secrets.token_hex(8))
JOB_RENOMMER = "0000000000000a06"
JOB_RATTRAPE = "00000000f1500001"   # fin enregistrée par le ctl, renvoyée par l'agent à son démarrage (fins-recentes, I4)


def figer_support(monkeypatch) -> None:
    """Identifiant de session de support figé, pour api.main seulement : les msg_id des files restent tirés au hasard."""
    monkeypatch.setattr(api_main, "secrets", types.SimpleNamespace(token_hex=lambda n=8: SUPPORT_ID))


def code_factice(nom: str = "gk9") -> str:
    """Code sbxmesh1 au bon format (somme de contrôle juste) mais sans aucun jeton réel."""
    charge = base64.urlsafe_b64encode(json.dumps({"a": "10.10.0.1", "n": nom, "t": "fa" * 32}, separators=(",", ":")).encode())
    charge = charge.decode().rstrip("=")
    return f"sbxmesh1.{charge}.{hashlib.sha256(charge.encode()).hexdigest()[:4]}"


class Maitre:
    """Le vrai contrôleur du maître (API, inventaire, suivi), sur une box du propriétaire (gk5, maillage) ; la box est jouée par le test."""

    def __init__(self, tmp_path: Path) -> None:
        self.h = Horloge()
        self.s = StockageSqlite(tmp_path / "p", horloge=self.h)
        self.f = Files()
        self.lignes: list = []
        self.inv = Inventaire(self.f, self.s, horloge=self.h)
        self.suivi = Suivi(self.s, self.f, self.audit, emettre=lambda nom: code_factice(nom))
        self.app = creer_app_admin(self.s, self.f, self.inv, self.audit, horloge=self.h, delai_lecture_s=2, suivi=self.suivi,
                                   noms_pris=set, delai_action_s=2)
        self.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "alice"}
        self.s.vu(GK5, {})

    def audit(self, evenement, champs):
        self.lignes.append((evenement, dict(champs)))

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://t")

    async def prendre(self) -> dict:
        """La requête que le maître vient de déposer pour gk5 (comme l'agent la reçoit au sondage)."""
        (rq,) = await self.f.attendre_requetes(GK5.cle, 2)
        return rq

    def repondre(self, rq: dict, type_: str, corps: dict) -> None:
        assert self.f.livrer_reponse(GK5.cle, {"msg_id": rq["msg_id"], "type": type_, "body": corps})


# Les actions de l'API : nom de fixture -> (route, corps JSON). Confirmation forte : gk5 est une box du propriétaire.
ACTIONS = {
    "operate_reboot": ("/boxes/gk5/actions/reboot", {"confirmation": "gk5"}),
    "operate_maj_paquets": ("/boxes/gk5/actions/maj-paquets", {}),
    "operate_service_demarrer": ("/boxes/gk5/actions/service-demarrer", {"args": {"unite": "secubox-hub.service"}}),
    "operate_service_arreter": ("/boxes/gk5/actions/service-arreter", {"args": {"unite": "secubox-hub.service"}, "confirmation": "gk5"}),
    "operate_service_redemarrer": ("/boxes/gk5/actions/service-redemarrer", {"args": {"unite": "secubox-hub.service"}}),
    "operate_renommer": ("/boxes/gk5/actions/renommer", {"args": {"nom": "gk9"}, "confirmation": "gk5"}),
    "operate_renouveler": ("/boxes/gk5/actions/renouveler", {"confirmation": "gk5"}),
}
ATTENDUES = sorted(["get_inventaire", "get_lire", "get_supported_dm", "operate_releve", "operate_support_ouvrir", "operate_support_fermer",
                    "operate_rejoindre", *ACTIONS])


async def _appel(m: Maitre, methode: str, url: str, corps=None):
    async with m.client() as c:
        return await c.request(methode, url, json=corps)


async def produire(tmp_path: Path, monkeypatch) -> dict:
    """{nom: {type, body}} : ce que le VRAI maître dépose dans la file de la box, pour chaque producteur."""
    figer_support(monkeypatch)
    m = Maitre(tmp_path)
    out: dict = {}

    async def capter(nom, appel, type_rep, corps_rep):
        t = asyncio.create_task(appel)
        rq = await m.prendre()
        out[nom] = {"type": rq["type"], "body": rq["body"]}
        m.repondre(rq, type_rep, corps_rep)
        return await t

    # relève périodique de l'inventaire (Inventaire.tour)
    await m.inv.tour()
    rq = await m.prendre()
    out["get_inventaire"] = {"type": rq["type"], "body": rq["body"]}
    m.repondre(rq, "GET_RESP", {"results": [{"path": "Device.", "params": {"Device.DeviceInfo.UpTime": 1}}]})
    await m.inv.attendre_fin()
    # lecture en direct
    r = await capter("get_lire", _appel(m, "GET", "/boxes/gk5/lire?chemin=Device.DeviceInfo.UpTime"),
                     "GET_RESP", {"results": [{"path": "Device.DeviceInfo.UpTime", "params": {"Device.DeviceInfo.UpTime": 1}}]})
    assert r.status_code == 200, r.text
    # GetSupportedDM : la forme du producteur du maître (pilotage.files.requete_modele)
    out["get_supported_dm"] = requete_modele()
    # relevé de performance à la demande
    r = await capter("operate_releve", _appel(m, "POST", "/boxes/gk5/releve", {"duree_s": 10}), "OPERATE_RESP", {"output": {}})
    assert r.status_code == 202, r.text
    # actions du catalogue
    for i, (nom, (url, corps)) in enumerate(ACTIONS.items()):
        job = JOB_RENOMMER if nom == "operate_renommer" else f"{i + 1:016x}"
        r = await capter(nom, _appel(m, "POST", url, corps), "OPERATE_RESP", {"etat": "accepte", "job": job, "raison": ""})
        assert r.status_code == 200 and r.json()["etat"] == "accepte", (nom, r.text)
    # support : ouverture puis fermeture
    r = await capter("operate_support_ouvrir", _appel(m, "POST", "/boxes/gk5/support", {"duree_min": 30}), "OPERATE_RESP",
                     {"etat": "consentement", "job": "", "raison": "consentement requis"})
    assert r.status_code == 200 and r.json()["id"] == SUPPORT_ID, r.text
    r = await capter("operate_support_fermer", _appel(m, "DELETE", f"/boxes/gk5/support/{SUPPORT_ID}"), "OPERATE_RESP",
                     {"etat": "accepte", "job": "", "raison": ""})
    assert r.status_code == 200, r.text
    # Rejoindre : suite d'un renommage réussi (fin X_SECUBOX_OperationDone, Suivi), code factice
    op = m.s.notification(GK5, {"type": TYPE_FIN, "job": JOB_RENOMMER, "rc": 0, "resume": "renommer : succès", "ts": 1})
    assert op is not None and op["action"] == "renommer"
    await m.suivi.apres_fin(GK5, op)
    rq = await m.prendre()
    out["operate_rejoindre"] = {"type": rq["type"], "body": rq["body"]}
    m.repondre(rq, "OPERATE_RESP", {"etat": "accepte", "job": "0000000000000b01", "raison": ""})
    await m.suivi.attendre()
    await m.suivi.arreter()
    return out


def _fixture(requete: dict) -> bytes:
    return (json.dumps({"route": "/canal/v1/requetes", "requete": requete}, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode()


def comparer(emises: dict, dossier: Path) -> None:
    """AssertionError si les fixtures de `dossier` ne sont pas exactement ce que le maître émet."""
    presentes = sorted(f.stem for f in dossier.glob("*.json"))
    assert presentes == ATTENDUES, "fixture orpheline ou manquante dans " + str(dossier)
    for nom, rq in emises.items():
        assert (dossier / f"{nom}.json").read_bytes() == _fixture(rq), (
            f"fixture {nom} périmée : le maître n'émet plus ce que l'agent rejoue (SECUBOX_CONTRAT_MAJ=1, puis le test Go)")


@pytest.mark.asyncio
async def test_le_maitre_emet_exactement_les_requetes_figees(tmp_path, monkeypatch):
    """Ce que le vrai maître émet = les fixtures que l'agent rejoue ; une requête changée (ou une fixture altérée) échoue ici."""
    emises = await produire(tmp_path, monkeypatch)
    assert sorted(emises) == ATTENDUES
    if MAJ:
        MAITRE.mkdir(parents=True, exist_ok=True)
        for nom, rq in emises.items():
            (MAITRE / f"{nom}.json").write_bytes(_fixture(rq))
    comparer(emises, MAITRE)


@pytest.mark.asyncio
@pytest.mark.parametrize("nom,avant,apres", [("operate_service_redemarrer", '"unite"', '"unit"'),
                                             ("operate_reboot", "Device.Reboot()", "Device.Redemarrer()"),
                                             ("get_inventaire", '"Device."', '"Device.DeviceInfo."')])
async def test_une_fixture_du_maitre_alteree_echoue(tmp_path, monkeypatch, nom, avant, apres):
    """Côté maître : une fixture altérée ne correspond plus à ce que le vrai contrôleur émet (le test Go échoue de son côté)."""
    emises = await produire(tmp_path, monkeypatch)
    copie = tmp_path / "maitre"
    copie.mkdir()
    for f in MAITRE.glob("*.json"):
        (copie / f.name).write_bytes(f.read_bytes())
    texte = (copie / f"{nom}.json").read_text(encoding="utf-8")
    assert avant in texte
    (copie / f"{nom}.json").write_text(texte.replace(avant, apres, 1), encoding="utf-8")
    with pytest.raises(AssertionError):
        comparer(emises, copie)


@pytest.mark.asyncio
async def test_rejoindre_ne_porte_qu_un_code_factice(tmp_path, monkeypatch):
    emises = await produire(tmp_path, monkeypatch)
    code = emises["operate_rejoindre"]["body"]["args"]["code"]
    charge = json.loads(base64.urlsafe_b64decode(code.split(".")[1] + "=="))
    assert charge["t"] == "fa" * 32 and code == code_factice("gk9")


# --- second volet : ce que l'agent émet pour L2 (fixtures agent-l2/, figées par le test Go), rejoué contre le vrai maître ---

AGENT_L2_ATTENDUES = sorted([*(f"reponse_{n}" for n in ATTENDUES if n.startswith("operate_")),
                             "notify_operation_progress", "notify_operation_done", "notify_operation_done_rattrapee", "notify_hands_tied",
                             "notify_consent", "notify_support"])
GK5_IP = {"X-Real-IP": GK5.adresse, "X-SecuBox-Pilotage-Tunnel": "1"}


def lire_agent_l2(dossier: Path = AGENT_L2) -> dict:
    return {f.stem: json.loads(f.read_text(encoding="utf-8")) for f in sorted(dossier.glob("*.json"))}


async def rejouer_agent_l2(tmp_path: Path, fx: dict, monkeypatch) -> list:
    """Rejoue les émissions de L2 de l'agent contre le vrai maître (API, canal, stockage, suivi assemblés comme en production) et
    vérifie ce que le maître en retient. AssertionError si une émission n'est pas comprise. Rend les lignes d'audit."""
    from api.asgi import assembler

    figer_support(monkeypatch)
    h = Horloge(1_793_000_000.0)                     # l'instant des fixtures de l'agent (fin de support à +30 min)
    s = StockageSqlite(tmp_path / "p", horloge=h)
    f = Files()
    lignes: list = []
    admin, canal = assembler(s, f, Inventaire(f, s, horloge=h), lambda ev, ch: lignes.append((ev, dict(ch))),
                             lambda a: GK5 if a == GK5.adresse else None, h, emettre=lambda nom: code_factice(nom))
    admin.dependency_overrides[auth.require_jwt] = lambda: {"sub": "alice"}
    s.vu(GK5, {})

    async def servir(nom: str):
        """La box prend la requête déposée par le maître (celle à laquelle l'agent a répondu) et poste la réponse figée de l'agent."""
        (rq,) = await f.attendre_requetes(GK5.cle, 2)
        assert {"type": rq["type"], "body": rq["body"]} == fx[nom]["requete"], f"{nom} : le maître ne demande plus ce que l'agent a reçu"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=canal), base_url="http://c", headers=GK5_IP) as c:
            r = await c.post("/canal/v1/reponses", json=[{**fx[nom]["envoi"], "msg_id": rq["msg_id"]}])
        assert r.status_code == 200 and r.json() == {"ignore": 0}, (nom, r.text)

    async def agir(nom: str, methode: str, url: str, corps=None):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=admin), base_url="http://a") as a:
            t = asyncio.create_task(a.request(methode, url, json=corps))
            await servir(nom)
            r = await t
        assert r.status_code in (200, 202), (nom, r.text)
        return r.json()

    async def notifier(nom: str):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=canal), base_url="http://c", headers=GK5_IP) as c:
            r = await c.post("/canal/v1/notifs", json=fx[nom]["envoi"])
        assert r.status_code == 200 and r.json() == {"ignore": 0}, (nom, r.text)

    jobs = {}
    for nom, (url, corps) in ACTIONS.items():
        rep, j = fx[f"reponse_{nom}"]["envoi"]["body"], await agir(f"reponse_{nom}", "POST", url, corps)
        assert (j["etat"], j["job"]) == (rep.get("etat"), rep.get("job")) and j["operation_etat"] == rep.get("etat"), (nom, j)
        jobs[nom] = j["job"]
    ops = {o["job"]: o for o in s.operations(GK5.cle)}
    assert {n: ops[jb]["etat"] for n, jb in jobs.items()} == {n: "accepte" for n in jobs}
    # relevé de performance : sortie du VRAI opérateur de l'agent, rangée par le vrai consommateur (suivre_releve)
    await agir("reponse_operate_releve", "POST", "/boxes/gk5/releve", {"duree_s": 10})
    for _ in range(200):
        rel = s.releve_lire(GK5.cle)
        if rel:
            break
        await asyncio.sleep(0.01)
    assert rel["statut"] == "ok" and rel["sortie"] == fx["reponse_operate_releve"]["envoi"]["body"]["output"], rel
    # support : demande (consentement de la box), puis notification « ouvert » avec sa fin
    j = await agir("reponse_operate_support_ouvrir", "POST", "/boxes/gk5/support", {"duree_min": 30})
    assert j["etat"] == fx["reponse_operate_support_ouvrir"]["envoi"]["body"]["etat"] == "consentement" and j["id"] == SUPPORT_ID
    await notifier("notify_support")
    ouvert = s.support_ouvert(GK5.cle, SUPPORT_ID)
    (ev_sup,) = [n["body"]["event"] for n in fx["notify_support"]["envoi"]]
    assert ouvert is not None and ouvert["etat"] == ev_sup["etat"] == "ouvert" and ouvert["fin"] is not None, ouvert
    # mains liées et consentement : événements rangés (type, id, état)
    await notifier("notify_hands_tied")
    await notifier("notify_consent")
    evs = {(e["type"], e["ident"], e["etat"]) for e in s.evenements(GK5.cle)}
    for n in fx["notify_hands_tied"]["envoi"] + fx["notify_consent"]["envoi"]:
        e = n["body"]["event"]
        assert (e["type"], e.get("id"), e.get("etat", e.get("decision"))) in evs, (e, evs)
    # progression puis fins : suivi du job, fin de chaque opération, Rejoindre après le renommage réussi
    await notifier("notify_operation_progress")
    (prog,) = [o for o in s.operations(GK5.cle) if o["job"] == jobs["operate_reboot"]]
    dernier = fx["notify_operation_progress"]["envoi"][-1]["body"]["event"]
    assert (prog["etape"], prog["pct"]) == (dernier["etape"], dernier["pct"]), prog
    await notifier("notify_operation_done")
    fins = {n["body"]["event"]["job"]: n["body"]["event"].get("rc") for n in fx["notify_operation_done"]["envoi"]}
    ops = {o["job"]: o for o in s.operations(GK5.cle)}
    for nom, jb in jobs.items():
        assert ops[jb]["etat"] == "termine" and ops[jb]["rc"] == fins[jb] == 0, (nom, ops[jb])
    # I4 (R-L2-47) : un reboot demandé avant le redémarrage de la box, dont l'agent n'a jamais remis la fin ; l'agent redémarré la
    # relit au ctl (fins-recentes) et la renvoie : le maître clôt l'opération
    rattrape = s.operation_demander(GK5.cle, "reboot", {}, "alice", None)
    s.operation_reponse(rattrape, "accepte", JOB_RATTRAPE, "")
    await notifier("notify_operation_done_rattrapee")
    (r,) = [o for o in s.operations(GK5.cle) if o["id"] == rattrape]
    (ev_r,) = [n["body"]["event"] for n in fx["notify_operation_done_rattrapee"]["envoi"]]
    assert ev_r["job"] == JOB_RATTRAPE and (r["etat"], r["resultat"], r["rc"]) == ("termine", "succes", 0), r
    await servir("reponse_operate_rejoindre")
    for _ in range(200):
        if any(ev == "pilotage_rejoindre_resultat" for ev, _ in lignes):
            break
        await asyncio.sleep(0.01)
    (res,) = [ch for ev, ch in lignes if ev == "pilotage_rejoindre_resultat"]
    assert res["etat"] == fx["reponse_operate_rejoindre"]["envoi"]["body"]["etat"] == "accepte", res
    # fermeture du support depuis le maître
    j = await agir("reponse_operate_support_fermer", "DELETE", f"/boxes/gk5/support/{SUPPORT_ID}")
    assert j["etat"] == fx["reponse_operate_support_fermer"]["envoi"]["body"]["etat"] == "accepte", j
    return lignes


def test_le_contrat_l2_couvre_les_emissions_de_l_agent():
    fx = lire_agent_l2()
    assert sorted(fx) == AGENT_L2_ATTENDUES, f"fixtures de l'agent orphelines ou manquantes dans {AGENT_L2}"
    types = {n["body"]["event"]["type"] for k, v in fx.items() if k.startswith("notify_") for n in v["envoi"]}
    assert types == {"X_SECUBOX_OperationProgress", "X_SECUBOX_OperationDone", "X_SECUBOX_HandsTied", "X_SECUBOX_Consent",
                     "X_SECUBOX_Support"}
    for k, v in fx.items():   # chaque réponse répond à une requête du maître telle qu'il l'émet aujourd'hui
        if k.startswith("reponse_"):
            assert v["requete"] == json.loads((MAITRE / f"{k[len('reponse_'):]}.json").read_text(encoding="utf-8"))["requete"], k


@pytest.mark.asyncio
async def test_le_maitre_comprend_ce_que_l_agent_emet_pour_l2(tmp_path, monkeypatch):
    """Réponses des actions (Reboot, MettreAJour, Services.Agir, Renommer, Renouveler, Support.Ouvrir/Fermer, Maillage.Rejoindre),
    réponse du relevé de performance et notifications de L2, telles que le VRAI agent les émet, rejouées contre le vrai maître."""
    lignes = await rejouer_agent_l2(tmp_path, lire_agent_l2(), monkeypatch)
    assert [ch["etat"] for ev, ch in lignes if ev == "pilotage_action" and ch["etat"] != "demande"] == ["accepte"] * len(ACTIONS)


def _alterer(fx: dict, nom: str, chemin: tuple, valeur=None, renommer: str = None) -> dict:
    fx = json.loads(json.dumps(fx))
    d = fx[nom]
    for k in chemin[:-1]:
        d = d[k]
    if renommer is not None:
        d[renommer] = d.pop(chemin[-1])
    else:
        d[chemin[-1]] = valeur
    return fx


@pytest.mark.asyncio
@pytest.mark.parametrize("nom,chemin,valeur,renommer", [
    ("reponse_operate_reboot", ("envoi", "body", "etat"), None, "état"),                       # clé renommée : refus inventé
    ("reponse_operate_renommer", ("envoi", "body", "job"), "0000000000000bad", None),            # autre job : fin non rattachée
    ("reponse_operate_releve", ("envoi", "type"), "OPERATE_RESPONSE", None),                     # type inconnu : ignoré
    ("notify_support", ("envoi", 0, "body", "event", "fin"), "2026-10-26 08:03:20", None),      # fin hors RFC 3339
    ("notify_operation_done", ("envoi", 0, "body", "event", "rc"), None, "code"),               # rc perdu
    ("notify_operation_done_rattrapee", ("envoi", 0, "body", "event", "job"), "00000000f15000ff", None),   # autre job : rien de clos
    ("notify_consent", ("envoi", 0, "body", "event", "decision"), "Accepté", None),              # hors liste fermée
])
async def test_une_emission_de_l_agent_alteree_echoue(tmp_path, monkeypatch, nom, chemin, valeur, renommer):
    """Côté maître : une fixture de l'agent altérée n'est plus comprise (le test Go échoue de son côté : l'agent n'émet pas cela)."""
    with pytest.raises(AssertionError):
        await rejouer_agent_l2(tmp_path, _alterer(lire_agent_l2(), nom, chemin, valeur, renommer), monkeypatch)
