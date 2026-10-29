# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2 tâche 6 — le canal accepte les champs des notifications de L2 (job, etape, pct, rc, resume ; id, etat,
decision, fin) au lieu de les jeter, les borne, et remet la fin d'une opération au suivi du maître une seule fois."""
import asyncio

from api.canal import _evenement, creer_app_canal
from pilotage.files import Files
from pilotage.stockage import StockageSqlite
from outils import Horloge
from test_canal import CONNUES, GK5, client


def notif(**ev):
    return {"type": "NOTIFY", "body": {"event": {"ts": 1, **ev}}}


def test_evenement_garde_les_champs_de_l2():
    assert _evenement(notif(type="X_SECUBOX_OperationProgress", job="a1b2c3d4e5f60718", etape="en_cours", pct=50)) == {
        "type": "X_SECUBOX_OperationProgress", "ts": 1, "job": "a1b2c3d4e5f60718", "etape": "en_cours", "pct": 50}
    assert _evenement(notif(type="X_SECUBOX_OperationDone", job="j1", rc=-1, resume="maj-paquets : résultat inconnu")) == {
        "type": "X_SECUBOX_OperationDone", "ts": 1, "job": "j1", "rc": -1, "resume": "maj-paquets : résultat inconnu"}
    assert _evenement(notif(type="X_SECUBOX_Support", id="s-1", etat="ouvert", fin="2026-10-29T12:30:00Z"))["fin"] == "2026-10-29T12:30:00Z"
    assert _evenement(notif(type="X_SECUBOX_Consent", id="c1", decision="refuse"))["decision"] == "refuse"
    # le résumé est un texte d'affichage : borné et sans caractère de contrôle
    r = _evenement(notif(type="X_SECUBOX_OperationDone", job="j1", rc=0, resume="ok\n" + "x" * 500))
    assert "\n" not in r["resume"] and len(r["resume"]) <= 200


def test_evenement_refuse_les_champs_de_l2_mal_formes():
    for ev in (dict(job="A B"), dict(job=""), dict(job="j" * 65), dict(job=5), dict(pct=101), dict(pct=-1), dict(pct=True),
               dict(pct=50.0), dict(rc=True), dict(rc="0"), dict(rc=1 << 40), dict(etape="EN COURS"), dict(etape=3),
               dict(id="../x"), dict(id="X"), dict(etat="ouvert;"), dict(decision=1), dict(fin="demain"), dict(fin=12),
               dict(fin="2026-10-29T12:30:00"), dict(resume=7)):
        assert _evenement(notif(type="T", **ev)) is None, ev


def test_fin_d_operation_remise_une_seule_fois_au_suivi(tmp_path):
    async def cas():
        s = StockageSqlite(tmp_path / "p", horloge=Horloge())
        fins = []

        async def apres_fin(box, op):
            fins.append((box.cle, op["job"], op["rc"]))

        app = creer_app_canal(Files(), CONNUES.get, s, lambda e, c: None, vu_intervalle_s=0, audit_intervalle_s=0, apres_fin=apres_fin)
        op = s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
        s.operation_reponse(op, "accepte", "job1", "")
        done = notif(type="X_SECUBOX_OperationDone", job="job1", rc=0, resume="maj-paquets : succès")
        async with client(app) as c:
            assert (await c.post("/canal/v1/notifs", json=[notif(type="X_SECUBOX_OperationProgress", job="job1", etape="en_cours", pct=50)]))\
                .json() == {"ignore": 0}
            assert (await c.post("/canal/v1/notifs", json=[done, done])).json() == {"ignore": 0}
        assert fins == [(GK5.cle, "job1", 0)]
        assert s.operations(GK5.cle)[0]["resultat"] == "succes"
    asyncio.run(cas())


def test_une_fin_n_est_jamais_perdue_sous_le_plafond_des_notifications(tmp_path):
    """L'agent retire une fin de sa boîte dès le 2xx : une fin comptée « ignorée » serait perdue pour toujours. Les fins ont
    leur propre fenêtre, séparée de celle des autres événements."""
    async def cas():
        s = StockageSqlite(tmp_path / "p", horloge=Horloge())
        app = creer_app_canal(Files(), CONNUES.get, s, lambda e, c: None, vu_intervalle_s=0, audit_intervalle_s=0,
                              horloge=lambda: 1000.0, notifs_par_minute=4)
        async with client(app) as c:
            assert (await c.post("/canal/v1/notifs", json=[notif(type="X_SECUBOX_Boot", value=1)] * 6)).json() == {"ignore": 2}
            r = await c.post("/canal/v1/notifs", json=[notif(type="X_SECUBOX_OperationDone", job="job1", rc=0)])
            assert r.json() == {"ignore": 0}
        assert s.operations(GK5.cle)[0]["job"] == "job1"
    asyncio.run(cas())


def test_crochet_en_erreur_ne_casse_pas_la_remise(tmp_path, caplog):
    async def cas():
        s = StockageSqlite(tmp_path / "p", horloge=Horloge())

        async def apres_fin(box, op):
            raise RuntimeError("panne")

        app = creer_app_canal(Files(), CONNUES.get, s, lambda e, c: None, vu_intervalle_s=0, audit_intervalle_s=0, apres_fin=apres_fin)
        async with client(app) as c:
            r = await c.post("/canal/v1/notifs", json=[notif(type="X_SECUBOX_OperationDone", job="job1", rc=0)])
            assert r.status_code == 200 and r.json() == {"ignore": 0}
    asyncio.run(cas())
