# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2794 — un seul etat par service : la Vue d'ensemble suit la sonde de sante comme la page Espaces.

Constat gk2 : « 39 a l'arret » alors que rlevel, proxypac, haproxy... sont montes dans l'agregateur (sonde `ok`) et grafana/hub en veille ;
les pages du hub (apercu, health) n'avaient aucune sonde et s'affichaient a l'arret."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")
apercu = importlib.import_module("apercu")


def menu(*items):
    return {"espaces": [{"id": "e", "nom": "E", "icone": "x", "items": [{"id": i, "active": a, "installed": True} for i, a in items]}]}


def arretes(m, sante):
    return apercu.construire_apercu(m, {}, [], 1, sante)["espaces"][0]["arretes"]


def test_un_module_monte_ou_en_veille_n_est_pas_arrete():
    sante = {"proxypac": {"status": "ok", "msg": "Monté dans l'agrégateur"}, "grafana": {"status": "ok", "veille": True}}
    assert arretes(menu(("proxypac", False), ("grafana", False)), sante) == []


def test_une_sonde_en_erreur_reste_arretee_meme_si_l_unite_est_active():
    assert arretes(menu(("waf", True)), {"waf": {"status": "error", "msg": "failed"}}) == ["waf"]


def test_un_module_degrade_n_est_pas_compte_arrete():
    assert arretes(menu(("x", False)), {"x": {"status": "warn", "msg": "inactive/dead"}}) == []


def test_sans_sonde_le_champ_active_reste_le_repli():
    assert arretes(menu(("a", False), ("b", True)), {}) == ["a"]
    assert arretes(menu(("a", False)), None) == ["a"]


def test_les_pages_du_hub_ont_une_sonde():
    m = {}
    main.superposer_montes(m, frozenset())
    for page in ("apercu", "health"):
        assert m[page]["status"] == "ok", page
