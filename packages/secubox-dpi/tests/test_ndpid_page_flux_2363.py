# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet Flux de nDPId au profil Aurora (#2363) : page autonome, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "www" / "ndpid" / "flux.html"


def texte():
    return PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in texte()


def test_message_de_hauteur_et_onglet():
    t = texte()
    assert "sbxNdpidVue" in t and "onglet:'flux'" in t and "location.origin" in t


def test_demo_et_embed():
    t = texte()
    assert "get('demo')" in t and "DONNÉES DE DÉMONSTRATION" in t and "get('embed')" in t


def test_aucune_ressource_externe():
    t = texte()
    assert not re.search(r"<script[^>]+src\s*=", t, re.I)
    assert not re.search(r"<link[^>]+href\s*=\s*[\"']https?:", t, re.I)
    assert "min-height:100vh" not in t


def test_pas_de_lorem_ni_secret():
    t = texte().lower()
    assert "lorem" not in t
    for mot in ("password", "passwd", "secret", "api_key", "apikey"):
        assert mot not in t
    assert not re.search(r"bearer [a-z0-9._-]{20,}", t)


def test_routes_de_l_api_citees_en_lecture_seule():
    t = texte()
    assert "/api/v1/ndpid/" in t
    for r in ("status", "flows", "stats/realtime"):
        assert r in t
    assert "method:'POST'" not in t and 'method:"POST"' not in t


def test_adresses_de_demo_rfc5737():
    t = texte()
    ips = set(re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", t[t.index("var DEMO"):t.index("function heure")]))
    assert ips and all(i.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for i in ips)
