# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3702 tâche 1 — l'action et le relevé vivent dans api/actions.py : mêmes gardes et même audit que la route."""
import asyncio

import pytest
from fastapi import HTTPException

from api import actions
from api.actions import ActionIn
from outils import GK5, Horloge
from pilotage.stockage import StockageSqlite
from test_operations_api import ACCEPTE, m  # noqa: F401  (monde de test et fixture)


@pytest.mark.asyncio
async def test_executer_action_du_module_meme_audit_que_la_route(m):
    ctx = m.app.state.contexte
    t = asyncio.create_task(actions.executer_action(ctx, "gk5", "reboot", ActionIn(confirmation="gk5"), {"sub": "alice"}))
    await m.repondre(GK5, ACCEPTE)
    r = await t
    assert r["etat"] == "accepte" and [e for e, _ in m.lignes] == ["pilotage_action", "pilotage_action"]


@pytest.mark.asyncio
async def test_executer_action_garde_la_confirmation_forte(m):
    ctx = m.app.state.contexte
    with pytest.raises(HTTPException) as e:
        await actions.executer_action(ctx, "gk5", "reboot", ActionIn(), {"sub": "alice"})
    assert e.value.status_code == 400 and m.lignes == []


@pytest.mark.asyncio
async def test_lancer_releve_refuse_un_second_releve(m):
    ctx = m.app.state.contexte
    b = await actions.trouver(ctx, "gk5")
    t = await actions.lancer_releve(ctx, b, 10, "alice")
    assert t in ctx.taches and b["cle"] in ctx.releves_en_cours
    with pytest.raises(HTTPException) as e:
        await actions.lancer_releve(ctx, b, 10, "alice")
    assert e.value.status_code == 409
    assert [x for x, _ in m.lignes] == ["pilotage_releve_demande"]
    await asyncio.sleep(0)   # la tâche démarre (une tâche annulée avant son premier pas ne libère rien)
    t.cancel()
    await asyncio.gather(t, return_exceptions=True)
    assert b["cle"] not in ctx.releves_en_cours


@pytest.mark.asyncio
async def test_lancer_releve_sans_audit_pas_de_releve(m):
    ctx = m.app.state.contexte
    b = await actions.trouver(ctx, "gk5")
    m.audit_ko = True
    with pytest.raises(HTTPException) as e:
        await actions.lancer_releve(ctx, b, 10, "alice")
    assert e.value.status_code == 503 and b["cle"] not in ctx.releves_en_cours and not ctx.taches


def test_operation_lire(tmp_path):
    s = StockageSqlite(tmp_path / "p", horloge=Horloge())
    s.vu(GK5, {})
    assert s.operation_lire(999) is None
    op = s.operation_demander(GK5.cle, "reboot", {}, "alice", None)
    ligne = s.operation_lire(op)
    assert ligne == next(x for x in s.operations() if x["id"] == op)
    assert ligne["action"] == "reboot" and ligne["nom"] == "gk5"
