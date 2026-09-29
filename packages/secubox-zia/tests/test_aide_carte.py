# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""ZIA décrit une carte du Hall depuis la source partagée (#1664)."""
import asyncio

from api import runtime


def test_question_de_carte_repond_par_la_source(monkeypatch):
    vus = []

    async def fausse(cfg, msg):
        vus.append(msg)
        return {"id": "radio", "ic": "📻", "nom": "Radio",
                "phrase": "Radio : la webradio du parc. En ce moment : 2 auditeurs."}

    monkeypatch.setattr(runtime, "_carte_du_hall", fausse)
    r = asyncio.run(runtime.respond("à quoi sert la carte Radio ?", "guest", None, {}))
    assert r["text"].startswith("Radio : ") and "2 auditeurs" in r["text"]
    assert r["carte"]["id"] == "radio" and vus


def test_une_commande_n_est_pas_une_question():
    assert not runtime._Q_CARTE.search("mets la carte radio en grand")
    assert not runtime._Q_CARTE.search("baisse le son")
    for q in ("c'est quoi zigbee", "explique la carte dpi", "à quoi sert mes comptes",
              "qu'est-ce que le surf & viewer", "aide sur la carte cloud"):
        assert runtime._Q_CARTE.search(q), q


def test_carte_inconnue_retombe_sur_le_chemin_ordinaire(monkeypatch):
    async def rien(cfg, msg):
        return None

    monkeypatch.setattr(runtime, "_carte_du_hall", rien)
    r = asyncio.run(runtime.respond("c'est quoi l'aide", "guest", None, {}))
    assert "carte" not in r
