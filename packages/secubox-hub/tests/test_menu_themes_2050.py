# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 vague 1 : le menu expose aussi un regroupement par `theme` (onglets du Hall), sans toucher aux catégories."""
from api import main as hub


def _calcule(monkeypatch, entrees, installes):
    monkeypatch.setattr(hub, "_load_menu_definitions", lambda: entrees)
    monkeypatch.setattr(hub, "_epingles_off", lambda: set())
    monkeypatch.setattr(hub, "_check_module_installed", lambda m: m in installes)
    monkeypatch.setattr(hub, "_check_module_active", lambda m: m in installes)
    return hub._compute_menu_sync()


ENTREES = [
    {"id": "qos", "name": "QoS", "category": "mesh", "order": 220, "theme": "reseau"},
    {"id": "dns", "name": "DNS", "category": "mesh", "order": 210, "theme": "reseau"},
    {"id": "waf", "name": "WAF", "category": "wall", "order": 105, "theme": "bouclier"},
    {"id": "vieux", "name": "Sans thème", "category": "wall", "order": 300},
]


def test_regroupement_par_theme_des_seuls_modules_installes(monkeypatch):
    res = _calcule(monkeypatch, ENTREES, {"qos", "dns", "waf", "vieux"})
    th = {t["id"]: [i["id"] for i in t["items"]] for t in res["themes"]}
    assert th["reseau"] == ["dns", "qos"]          # triés par ordre
    assert th["bouclier"] == ["waf"]
    assert th["autre"] == ["vieux"]                # une entrée sans thème n'est jamais perdue


def test_un_module_absent_n_apparait_pas_dans_les_themes(monkeypatch):
    res = _calcule(monkeypatch, ENTREES, {"waf"})
    assert [t["id"] for t in res["themes"]] == ["bouclier"]


def test_les_categories_restent_inchangees(monkeypatch):
    res = _calcule(monkeypatch, ENTREES, {"qos", "dns", "waf", "vieux"})
    assert {c["id"] for c in res["categories"]} == {"mesh", "wall"}
