# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Toute entrée menu.d du DÉPÔT est dans l'une des six catégories de la charte (#1552).

DevWatch et ZIA déclaraient « systeme » : le Hall range le menu Système par
les six catégories, ils n'apparaissaient dans aucun groupe. gabriel-mood
avait des clés françaises (label/url/categorie) : sans `path`, le Hall
l'envoyait sur « / ». Ce test lit les fichiers, pas une box."""
import json
from pathlib import Path

import pytest

PAQUETS = Path(__file__).resolve().parents[2]
SIX = {"auth", "wall", "boot", "mind", "root", "mesh"}
ENTREES = sorted(p for p in PAQUETS.glob("*/menu.d/*.json") if "/debian/" not in str(p))


def test_le_referentiel_est_celui_du_hub():
    import re
    src = (PAQUETS / "secubox-hub" / "api" / "main.py").read_text()
    bloc = src[src.index("CATEGORY_META = {"):]
    bloc = bloc[:bloc.index("\n}\n")]
    assert set(re.findall(r'^\s+"([a-z]+)": \{', bloc, re.M)) == SIX


@pytest.mark.parametrize("f", ENTREES, ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_entree_menu_conforme(f):
    d = json.loads(f.read_text())
    for cle in ("id", "name", "category"):
        assert d.get(cle), f"clé « {cle} » absente"
    assert d["category"] in SIX, f"catégorie « {d['category']} » hors charte"
    if not d.get("console_only"):                  # console TTY : pas de page, le hub l'écarte
        assert str(d.get("path") or "").startswith("/"), "chemin absent : le Hall enverrait sur « / »"
