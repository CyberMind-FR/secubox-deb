# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Toolbox — page Aurora de l'onglet Sentinelle (#2373) : contrat statique."""
from __future__ import annotations

import re
from pathlib import Path

from starlette.routing import Route

from secubox_toolbox.app import app

PAGE = Path(__file__).resolve().parents[1] / "www" / "toolbox" / "sentinelle.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx_et_licence():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:400]


def test_postmessage_et_demo():
    assert "sbxToolboxVue" in SRC
    assert "onglet:'sentinelle'" in SRC
    assert "demo" in SRC and "DONNÉES DE DÉMONSTRATION" in SRC
    assert "embed" in SRC


def test_aucune_ressource_externe():
    assert not re.search(r"<script[^>]+src=", SRC, re.I)
    assert not re.search(r"""(?:href|src)=["']https?://""", SRC, re.I)
    assert "@import" not in SRC


def test_pas_de_dialogue_natif_ni_lorem_ni_secret():
    assert not re.search(r"\b(?:confirm|alert|prompt)\(", SRC)
    assert "lorem" not in SRC.lower()
    assert not re.search(r"(?i)(?:BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]|secret\s*[:=])", SRC)


def test_routes_lecture_citees_et_existantes():
    for r in ("/stats", "/verdicts", "/c2"):
        assert "/admin/sentinel" + r in SRC
    assert "/api/v1/toolbox" in SRC
    paths = {(m, p.path) for p in app.routes if isinstance(p, Route) for m in (p.methods or ())}
    for r in ("/admin/sentinel/stats", "/admin/sentinel/verdicts", "/admin/sentinel/c2"):
        assert ("GET", r) in paths


def test_action_ecriture_identique_a_l_ancien_onglet():
    assert "/admin/sentinel/c2/allow" in SRC
    assert "method:'POST'" in SRC
    assert "'Content-Type':'application/x-www-form-urlencoded'" in SRC
    assert "'host='+encodeURIComponent(host)" in SRC
    assert "credentials:'same-origin'" in SRC
    paths = {(m, p.path) for p in app.routes if isinstance(p, Route) for m in (p.methods or ())}
    assert ("POST", "/admin/sentinel/c2/allow") in paths


def test_demo_n_ecrit_pas():
    assert "if(DEMOMODE){BUSY=false;" in SRC
