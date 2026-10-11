# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet « Risques » de nDPId au profil Aurora : page autonome, lecture seule, sans librairie externe, sans secret."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "www" / "ndpid" / "risques.html"


def texte():
    return PAGE.read_text(encoding="utf-8")


def test_spdx_cmsd():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in texte()


def test_contrat_page_encadree():
    t = texte()
    assert "sbxNdpidVue" in t and "onglet:'risques'" in t
    assert "postMessage" in t and "location.origin" in t
    assert "min-height:100vh" not in t.replace(" ", "")


def test_demo_et_embed():
    t = texte()
    assert "demo" in t and "DONNÉES DE DÉMONSTRATION" in t
    assert "embed" in t


def test_route_api_citee_et_lecture_seule():
    t = texte()
    assert "/api/v1/ndpid/" in t
    assert "method:'POST'" not in t and 'method:"POST"' not in t


def test_aucune_librairie_externe():
    t = texte()
    assert not re.search(r"<script[^>]+src\s*=", t, re.I)
    assert "cdn" not in t.lower()
    assert "@import" not in t


def test_ni_lorem_ni_secret():
    t = texte().lower()
    assert "lorem" not in t
    for motif in ("password", "passwd", "secret", "api_key", "apikey", "bearer ey"):
        assert motif not in t.replace("authorization", ""), motif
