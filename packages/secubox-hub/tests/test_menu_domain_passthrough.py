# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Garde de régression (#1175 Task 4) : `domain`/`same_origin` posés par un
drop-in `menu.d` doivent survivre à `_compute_menu_sync`, car
`api.idmap.resolve()` (secubox-webos) en dépend en aval pour la jointure
id↔domaine. `_compute_menu_sync` construit chaque item via `item.copy()`
(copie complète) : ce test casse si un futur refactor se met à ne recopier
qu'une liste de champs "connus" et oublie domain/same_origin.
"""
from api import main as hub


def test_domain_et_same_origin_survivent_a_compute_menu_sync(monkeypatch):
    items = [
        {
            "id": "testmod",
            "category": "other",
            "domain": "testmod.gk2.secubox.in",
        },
        {
            "id": "othermod",
            "category": "other",
            "same_origin": True,
        },
    ]
    monkeypatch.setattr(hub, "_load_menu_definitions", lambda: items)
    monkeypatch.setattr(hub, "_check_module_installed", lambda module_id: True)
    monkeypatch.setattr(hub, "_check_module_active", lambda module_id: True)
    monkeypatch.setattr(hub, "_epingles_off", lambda: set())

    menu = hub._compute_menu_sync()

    resolved = {
        i["id"]: i
        for cat in menu["categories"]
        for i in cat["items"]
    }
    assert resolved["testmod"]["domain"] == "testmod.gk2.secubox.in"
    assert resolved["othermod"]["same_origin"] is True
