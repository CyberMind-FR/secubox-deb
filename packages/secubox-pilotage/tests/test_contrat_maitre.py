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
    monkeypatch.setattr(api_main.secrets, "token_hex", lambda n=8: SUPPORT_ID)
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


@pytest.mark.asyncio
async def test_le_maitre_emet_exactement_les_requetes_figees(tmp_path, monkeypatch):
    """Ce que le vrai maître émet = les fixtures que l'agent rejoue ; une requête changée (ou une fixture altérée) échoue ici."""
    emises = await produire(tmp_path, monkeypatch)
    assert sorted(emises) == ATTENDUES
    if MAJ:
        MAITRE.mkdir(parents=True, exist_ok=True)
        for nom, rq in emises.items():
            (MAITRE / f"{nom}.json").write_bytes(_fixture(rq))
    presentes = sorted(f.stem for f in MAITRE.glob("*.json"))
    assert presentes == ATTENDUES, "fixture orpheline ou manquante dans " + str(MAITRE)
    for nom, rq in emises.items():
        assert (MAITRE / f"{nom}.json").read_bytes() == _fixture(rq), (
            f"fixture {nom} périmée : le maître n'émet plus ce que l'agent rejoue (SECUBOX_CONTRAT_MAJ=1, puis le test Go)")


@pytest.mark.asyncio
async def test_rejoindre_ne_porte_qu_un_code_factice(tmp_path, monkeypatch):
    emises = await produire(tmp_path, monkeypatch)
    code = emises["operate_rejoindre"]["body"]["args"]["code"]
    charge = json.loads(base64.urlsafe_b64decode(code.split(".")[1] + "=="))
    assert charge["t"] == "fa" * 32 and code == code_factice("gk9")
