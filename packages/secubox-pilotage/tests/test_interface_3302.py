# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3302 — bascule d'interface locale ⇄ distante depuis la Flotte : actions du catalogue (confirmation forte), et confirmation
automatique par le maître après une bascule vers « distante » réussie (preuve que le canal maître ⇄ box survit ; sans elle,
l'homme mort de la box rend l'interface locale)."""
import asyncio

import pytest
from fastapi.testclient import TestClient

from outils import GK5
from test_operations_api import Monde, fin, lancer

BASCULER = "Device.X_SECUBOX_Pilotage.Interface.Basculer()"
CONFIRMER = "Device.X_SECUBOX_Pilotage.Interface.Confirmer()"


@pytest.fixture
def m(tmp_path):
    w = Monde(tmp_path)
    w.s.vu(GK5, {})
    return w


@pytest.mark.parametrize("action", ["interface-distante", "interface-locale"])
def test_bascule_exige_la_confirmation_forte(m, action):
    c = TestClient(m.app)
    for corps in ({}, {"confirmation": "GK5"}, {"args": {"sens": "distante"}, "confirmation": "gk5"}):
        assert c.post(f"/boxes/gk5/actions/{action}", json=corps).status_code in (400, 422), corps
    assert m.f.en_attente(GK5.cle) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("action,sens", [("interface-distante", "distante"), ("interface-locale", "locale")])
async def test_bascule_envoyee_avec_son_sens(m, action, sens):
    async with m.client() as c:
        t = asyncio.create_task(c.post(f"/boxes/gk5/actions/{action}", json={"confirmation": "gk5"}))
        rq = await m.repondre(GK5, {"etat": "accepte", "job": "j1", "raison": ""})
        r = await t
    assert r.status_code == 200 and rq["body"]["command"] == BASCULER and rq["body"]["args"] == {"sens": sens}


@pytest.mark.asyncio
async def test_bascule_distante_reussie_confirmee_par_le_maitre(m):
    async with m.client() as c:
        await lancer(m, c, GK5, "interface-distante", {"confirmation": "gk5"}, "j1")
        await fin(m, GK5, "j1")
        rq = await m.repondre(GK5, {"etat": "accepte", "job": "", "raison": ""})
        await fin(m, GK5, "j1")                                    # renotification : une seule confirmation
        await m.suivi.attendre()
    assert rq["body"]["command"] == CONFIRMER and rq["body"]["args"] == {}
    assert m.f.en_attente(GK5.cle) == 0
    evs = [(e, ch.get("etat")) for e, ch in m.lignes if e.startswith("pilotage_interface")]
    assert evs == [("pilotage_interface_confirmation", "envoyee"), ("pilotage_interface_confirmation", "accepte")]


@pytest.mark.asyncio
async def test_pas_de_confirmation_apres_un_echec_ni_un_retour_en_locale(m):
    async with m.client() as c:
        await lancer(m, c, GK5, "interface-distante", {"confirmation": "gk5"}, "j1")
        await fin(m, GK5, "j1", rc=1)
        await lancer(m, c, GK5, "interface-locale", {"confirmation": "gk5"}, "j2")
        await fin(m, GK5, "j2")
        await m.suivi.attendre()
    assert m.f.en_attente(GK5.cle) == 0
    assert not [e for e, _ in m.lignes if e.startswith("pilotage_interface")]


@pytest.mark.asyncio
async def test_confirmation_refusee_auditee(m):
    async with m.client() as c:
        await lancer(m, c, GK5, "interface-distante", {"confirmation": "gk5"}, "j1")
        await fin(m, GK5, "j1")
        await m.repondre(GK5, {"etat": "refuse", "job": "", "raison": "rien à confirmer"})
        await m.suivi.attendre()
    (dernier,) = [ch for e, ch in m.lignes if e == "pilotage_interface_confirmation" and ch["etat"] != "envoyee"]
    assert dernier["etat"] == "refuse" and dernier["raison"] == "rien à confirmer"
