# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tranche B (#3992) : retours 👍/👎, corrections reprises, évaluation EvalRunner, routage appris — sur le VRAI moteur."""
import json
import os
import time
from pathlib import Path

import pytest

pytest.importorskip("openjarvis", reason="OpenJarvis absent : tests à lancer avec /opt/secubox-ai-agents/venv/bin/python (README)")

from conftest import PAQUET, moteur_present  # noqa: E402

reel = pytest.mark.skipif(not moteur_present(), reason="llama-server absent : test réel impossible ici")
SECOND = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "secubox-ai-eval/moteur.sock"
UNITE_EVAL = PAQUET / "systemd/secubox-ai-eval-moteur-gk0.service"


def _ev(r):
    return [json.loads(ligne[6:]) for ligne in r.text.splitlines() if ligne.startswith("data: ")]


def _texte(ev):
    return "".join(e.get("morceau", "") for e in ev)


def _attendre(c, ident, s=600):
    fin = time.time() + s
    while time.time() < fin:
        t = c.get(f"/travaux/{ident}").json()
        if t["etat"] != "en_cours":
            return t
        time.sleep(2)
    raise AssertionError("travail trop long")


# --- jeu et notation (sans moteur) -----------------------------------------------------------------------

def test_jeu_et_notation_deterministe():
    from openjarvis.evals.core.types import EvalRecord

    from agents.evaluation import JeuSecubox, MotsAttendus
    j = JeuSecubox()
    j.load()
    assert j.size() == 21 and {r.subject for r in j.iter_records()} == {"short", "general", "math", "code",
                                                                        "conversation", "raisonnement", "francais"}
    rec = EvalRecord(record_id="x", problem="q", reference=json.dumps([["web application firewall", "pare-feu applicatif"]]),
                     category="chat")
    assert MotsAttendus().score(rec, "C'est un Pare-feu APPLICATIF.")[0] is True
    assert MotsAttendus().score(rec, "un antivirus")[0] is False


def test_unite_eval_sans_lien_avec_poc_llama():
    t = UNITE_EVAL.read_text()
    lignes = [ligne for ligne in t.splitlines() if not ligne.startswith("#")]
    assert not [ligne for ligne in lignes if "poc-llama" in ligne]       # leçon d'After= (2026-11-26)
    assert "RuntimeMaxSec=3600" in lignes and "RestrictAddressFamilies=AF_UNIX" in lignes
    assert "[Install]" not in lignes                                      # jamais lancée seule
    assert "-ngl 0 --device none" in t                                    # la carte graphique reste au POC


def test_routage_appris_sur_traces_reelles(tmp_path):
    from openjarvis.core.types import Trace
    from openjarvis.traces.store import TraceStore

    from agents.evaluation import recommandation
    ts = TraceStore(str(tmp_path / "t.db"))
    for i in range(6):
        ts.save(Trace(query=f"question courte {i}", model="a.gguf", outcome="success", feedback=1.0))
        ts.save(Trace(query=f"question courte {i}", model="b.gguf", outcome="failure", feedback=0.0))
    r = recommandation(ts)
    assert r["carte"] == {"short": "a.gguf"} and r["appliquee"] is False


# --- retours et corrections (vrai moteur) ----------------------------------------------------------------

@reel
def test_retour_correction_change_la_reponse_suivante(client):
    q = "Quel est le nom de code de la prochaine box SecuBox ? Réponds en un mot."
    r = client.post("/chat", json={"message": q, "memoire": False, "max_tokens": 24, "temperature": 0})
    ev = _ev(r)
    trace = ev[-1]["trace"]
    assert trace and ev[0]["corrections"] == 0
    assert "aurochs" not in _texte(ev).lower()
    # 👎 + correction
    assert client.post("/retour", json={"trace": trace, "note": "moins", "correction": "Aurochs"}).status_code == 200
    assert client.post("/retour", json={"trace": "deadbeef", "note": "plus"}).status_code == 404
    # nouvelle conversation, même question : la correction est reprise
    ev2 = _ev(client.post("/chat", json={"message": q, "memoire": False, "max_tokens": 24, "temperature": 0}))
    assert ev2[0]["corrections"] >= 1
    assert "aurochs" in _texte(ev2).lower(), _texte(ev2)
    # le retour est dans le TraceStore d'OpenJarvis
    import agents.app as m  # noqa: F401
    assert client.app.state.traces.get(trace).feedback == 0.0


@reel
def test_evaluation_reelle_moteur_actif(client):
    r = client.post("/evaluation", json={"moteur": "actif", "echantillons": 4})
    assert r.status_code == 200
    t = _attendre(client, r.json()["travail"])
    assert t["etat"] == "fini", t
    h = client.get("/evaluation").json()
    x = h["historique"][0]
    assert x["moteur"] == "actif" and x["n"] == 4 and x["latence_s"] > 0 and x["premier_s"] > 0 and x["debit_js"] > 0
    assert len(client.app.state.traces.list_traces(agent="evaluation")) == 4
    # Fichiers d'EvalRunner sous l'état du service seulement (sans chemin, il écrit ./results : interdit en unité).
    assert not (Path.cwd() / "results").exists()
    assert list((Path(os.environ["SECUBOX_AI_AGENTS_ETAT"]) / "evaluations").glob("*.summary.json"))
    assert client.post("/evaluation", json={"moteur": "second"}).status_code in (200, 409)


@pytest.mark.skipif(not SECOND.is_socket(), reason="second moteur d'évaluation arrêté (le démarrer depuis /jarvis)")
def test_evaluation_reelle_second_moteur(client, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_AGENTS_MOTEUR2", str(SECOND))
    t = _attendre(client, client.post("/evaluation", json={"moteur": "second", "echantillons": 3}).json()["travail"],
                  1800)
    assert t["etat"] == "fini", t
