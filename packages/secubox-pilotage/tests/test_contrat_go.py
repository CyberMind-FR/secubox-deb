# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contrat Go ↔ Python (#3126, M14 de la relecture finale L1).

Les fixtures de `secubox-pilotage-agent/internal/canal/testdata/contrat/` sont les enveloppes que le VRAI client Go émet (son test
`TestContratEnveloppesEmises` échoue si elles ne correspondent plus). Ici, chacune est rejouée contre le VRAI canal (creer_app_canal) et, pour
les GET_RESP, rangée par le VRAI stockage SQLite. Les fichiers sont relus à chaque passe : une fixture régénérée côté Go est rejouée telle quelle.
"""
import asyncio
import json
from pathlib import Path

import pytest

from api.canal import creer_app_canal
from pilotage.files import Files
from pilotage.identite import Box
from pilotage.stockage import StockageMemoire, StockageSqlite

import httpx

CONTRAT = Path(__file__).resolve().parents[2] / "secubox-pilotage-agent" / "internal" / "canal" / "testdata" / "contrat"
GK5 = Box("gk5", "10.10.0.10", "maillage", None, None)
FIXTURES = sorted(CONTRAT.glob("*.json"))


def _lire(f: Path) -> dict:
    return json.loads(f.read_text(encoding="utf-8"))


def test_le_contrat_couvre_toutes_les_enveloppes():
    assert CONTRAT.is_dir(), f"dossier de contrat absent : {CONTRAT}"
    fx = [_lire(f) for f in FIXTURES]
    routes = {x["route"] for x in fx}
    assert routes == {"/canal/v1/bonjour", "/canal/v1/reponses", "/canal/v1/notifs"}
    types = {x["envoi"]["type"] for x in fx if x["route"] == "/canal/v1/reponses"}
    assert types == {"GET_RESP", "GET_SUPPORTED_DM_RESP", "OPERATE_RESP", "ERROR"}
    get = [x["envoi"]["body"] for x in fx if x["route"] == "/canal/v1/reponses" and x["envoi"]["type"] == "GET_RESP"]
    assert any(r.get("failed") for b in get for r in b["results"]) and any(b.get("tronque") is True for b in get)


async def _rejouer(fx: dict, tmp_path: Path):
    files, memoire = Files(), StockageMemoire()
    app = creer_app_canal(files, {GK5.adresse: GK5}.get, memoire, lambda *a: None, attente_max=0.05, vu_intervalle_s=0, audit_intervalle_s=0)
    tr = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=tr, base_url="http://m", headers={"X-Real-IP": GK5.adresse, "X-SecuBox-Pilotage-Tunnel": "1"}) as c:
        if fx["route"] == "/canal/v1/bonjour":
            r = await c.post(fx["route"], content=json.dumps(fx["envoi"]))
            assert r.status_code == 200, r.text
            infos = memoire.vus[-1][1]
            assert infos["agent_version"] == fx["envoi"]["agent_version"] and infos["boot_id"] == fx["envoi"]["boot_id"]
            assert infos["modele"] == fx["envoi"]["modele"] and infos["modele"]
            return None
        if fx["route"] == "/canal/v1/notifs":
            r = await c.post(fx["route"], content=json.dumps(fx["envoi"]))
            assert r.status_code == 200 and r.json() == {"ignore": 0}, r.text
            assert [ev for _, ev in memoire.notifications] == [n["body"]["event"] for n in fx["envoi"]]
            # N5 : rangées aussi par le VRAI stockage (types, unité, valeur, instant de la box)
            stock = StockageSqlite(tmp_path / "pilotage")
            stock.vu(GK5, {})
            for _, ev in memoire.notifications:
                stock.notification(GK5, ev)
            ranges = [(e["type"], e["unite"], e["valeur"], e["survenu_le"]) for e in reversed(stock.evenements(GK5.cle))]
            assert ranges == [(e["type"], e.get("unit"), e.get("value"), e["ts"]) for e in (n["body"]["event"] for n in fx["envoi"])]
            return None
        # réponse : le maître dépose la requête, la box la reçoit, puis poste l'enveloppe émise par le client Go (msg_id du dépôt)
        futur = files.deposer(GK5.cle, fx["requete"])
        r = await c.get("/canal/v1/requetes?attente=1")
        assert r.status_code == 200
        [servie] = r.json()
        assert {k: servie[k] for k in ("type", "body")} == fx["requete"]
        envoi = {**fx["envoi"], "msg_id": servie["msg_id"]}
        r = await c.post(fx["route"], content=json.dumps([envoi]))
        assert r.status_code == 200 and r.json() == {"ignore": 0}, r.text
    rep = await asyncio.wait_for(futur, 1)
    assert rep == envoi
    if rep["type"] == "GET_RESP":
        stock = StockageSqlite(tmp_path / "pilotage")
        stock.vu(GK5, {})
        assert stock.inventaire_enregistrer(GK5, rep["body"]) is True
        inv = stock.inventaire(GK5.cle)
        attendus = {k: v for res in rep["body"]["results"] for k, v in (res.get("params") or {}).items()}
        assert inv["valeurs"] == attendus
        degrade = rep["body"].get("tronque") is True or any(res.get("failed") or res.get("err") for res in rep["body"]["results"])
        assert inv["partiel"] is degrade
    return rep


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f.stem for f in FIXTURES])
def test_le_maitre_accepte_l_enveloppe_emise_par_le_client_go(fixture, tmp_path):
    asyncio.run(_rejouer(_lire(fixture), tmp_path))


def test_failed_et_tronque_donnent_une_releve_partielle(tmp_path):
    """Les deux cas qui comptent pour l'inventaire : une source en échec (`failed`) et une réponse coupée (`tronque`) ne doivent jamais
    effacer un relevé complet."""
    for nom in ("get_resp_failed", "get_resp_tronque"):
        rep = asyncio.run(_rejouer(_lire(CONTRAT / f"{nom}.json"), tmp_path / nom))
        assert rep["type"] == "GET_RESP"


async def _reboot_clos_par_le_bonjour(bonjour: dict, tmp_path: Path) -> list:
    """Le bonjour émis par le client Go (bonjour.json), rejoué deux fois contre le vrai canal et le vrai stockage : la seconde fois
    avec un autre boot_id (la box a redémarré). Rend les fins remises au suivi."""
    s = StockageSqlite(tmp_path / "pilotage")
    fins = []

    async def apres_fin(box, op):
        fins.append((op["job"], op["resultat"], op["resume"]))

    app = creer_app_canal(Files(), {GK5.adresse: GK5}.get, s, lambda *a: None, vu_intervalle_s=0, audit_intervalle_s=0,
                          apres_fin=apres_fin)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://m",
                                 headers={"X-Real-IP": GK5.adresse, "X-SecuBox-Pilotage-Tunnel": "1"}) as c:
        assert (await c.post("/canal/v1/bonjour", content=json.dumps(bonjour))).status_code == 200
        op = s.operation_demander(GK5.cle, "reboot", {}, "alice", None)
        s.operation_reponse(op, "accepte", "00000000000000b0", "")
        autre = {**bonjour, "boot_id": "ffffffff-0000-4000-8000-000000000000"} if "boot_id" in bonjour else bonjour
        assert (await c.post("/canal/v1/bonjour", content=json.dumps(autre))).status_code == 200
    return fins


def test_le_boot_id_du_bonjour_emis_clot_le_reboot(tmp_path):
    """I4 (R-L2-47) : le boot_id que le vrai client Go met dans son bonjour suffit au maître pour clore un reboot interrompu."""
    fx = _lire(CONTRAT / "bonjour.json")
    assert fx["envoi"]["boot_id"]
    fins = asyncio.run(_reboot_clos_par_le_bonjour(fx["envoi"], tmp_path))
    assert fins == [("00000000000000b0", "succes", "reboot : succès (redémarrée)")]


def test_un_bonjour_sans_boot_id_ne_clot_rien(tmp_path):
    """Fixture altérée (boot_id retiré) : le maître ne peut rien conclure, le reboot reste en cours."""
    fx = _lire(CONTRAT / "bonjour.json")
    sans = {k: v for k, v in fx["envoi"].items() if k != "boot_id"}
    assert asyncio.run(_reboot_clos_par_le_bonjour(sans, tmp_path)) == []
