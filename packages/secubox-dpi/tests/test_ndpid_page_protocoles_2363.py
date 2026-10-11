# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet Protocoles de nDPId (profil Aurora) : page autonome, lecture seule, sans dépendance externe."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "www" / "ndpid" / "protocoles.html"


def _src():
    return PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in _src()


def test_hauteur_et_demo():
    s = _src()
    assert "sbxNdpidVue" in s and "onglet:'protocoles'" in s
    assert "demo" in s and "DONNÉES DE DÉMONSTRATION" in s and "embed" in s


def test_routes_lues():
    s = _src()
    assert "/api/v1/ndpid/" in s
    for r in ("top/protocols", "top/applications", "status"):
        assert r in s


def test_aucun_script_externe_ni_secret():
    s = _src()
    assert not re.search(r"<script[^>]+src=", s, re.I)
    assert not re.search(r"https?://[^\s\"']*\.(js|css)", s)
    assert "lorem" not in s.lower()
    assert not re.search(r"(password|passwd|secret|api[_-]?key)\s*[:=]", s, re.I)
    assert "min-height:100vh" not in s.replace(" ", "")
