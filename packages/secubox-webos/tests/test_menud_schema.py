# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — garde-fou de schéma pour les drop-ins menu.d.

Vérifie que tout champ `domain`/`same_origin` posé dans un menu.d/*.json
est bien formé (jointure id↔domaine, Task 8). Passe trivialement tant
qu'aucun champ n'est encore présent — ce n'est pas un test TDD rouge, c'est
un garde-fou de non-régression pour l'enrichissement au fil de l'eau.
"""
import glob
import json
import os


def test_menud_domain_fields_are_wellformed():
    root = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages")
    paths = glob.glob(os.path.join(root, "*", "menu.d", "*.json"))
    assert paths, f"no menu.d/*.json found under {root!r} — path resolution broken?"
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data["items"] if "items" in data else [data]
        else:
            items = []
        for it in items:
            if not isinstance(it, dict):
                continue
            if "domain" in it:
                assert isinstance(it["domain"], str) and it["domain"], path
            if "same_origin" in it:
                assert isinstance(it["same_origin"], bool), path
