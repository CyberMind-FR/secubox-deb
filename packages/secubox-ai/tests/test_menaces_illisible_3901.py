# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3901 : une source de gk2 en erreur se lit « inconnu » (None), jamais 0 ; un résumé automatique en échec attend
l'intervalle comme un résumé réussi."""
import pytest

# ruff: noqa: F811 — les fixtures importées se redéclarent en paramètres

from api import menaces, taches
from tests.test_menaces_3583 import attendre, env, gk2, moteur_simule  # noqa: F401 — fixtures partagées


@pytest.mark.asyncio
@pytest.mark.parametrize("chemin,cle", [("/waf/bans", "bans_actifs"), ("/waf/campaigns", "campagnes"),
                                        ("/waf/alerts", "alertes_derniere_heure"), ("/waf/stats", "menaces_jour")])
async def test_source_en_erreur_chiffre_inconnu(gk2, chemin, cle):
    gk2["pannes"].add(chemin)
    r = await menaces.releve_menaces()
    assert chemin in r["erreurs"] and r["chiffres"][cle] is None


@pytest.mark.asyncio
async def test_sources_lues_chiffres_presents(gk2):
    r = await menaces.releve_menaces()
    assert r["erreurs"] == [] and isinstance(r["chiffres"]["bans_actifs"], int)
    assert isinstance(r["chiffres"]["campagnes"], int)


@pytest.mark.asyncio
async def test_resume_auto_en_echec_attend_l_intervalle(gk2, monkeypatch):
    moteur_simule(monkeypatch, "x")

    async def echoue(t, r):
        raise RuntimeError("moteur tombé")

    monkeypatch.setattr(menaces, "resumer_menaces", echoue)
    await menaces.releve_menaces()
    t = await menaces.tour_veille()
    assert t
    await attendre(t)
    assert taches.TACHES[t]["etat"] != "en_cours" and menaces.DERNIER_RESUME["quand"] == 0
    assert await menaces.tour_veille() is None          # l'échec compte pour l'intervalle
