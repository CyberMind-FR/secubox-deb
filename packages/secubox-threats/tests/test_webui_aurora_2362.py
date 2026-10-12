# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Webui threats au profil projet de référence Aurora (#2362) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "www" / "threats" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")

ROUTES = ["/status", "/timeline?hours=24&limit=100", "/scores", "/alerts?limit=", "/iocs?limit=15",
          "/incidents?limit=15", "/alerts/sources", "/feeds", "/reports"]


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML[:400]


def test_marqueurs_aurora():
    for m in ("sbxThreatsVue", "demo", "embed", "container-type:inline-size", "DONNÉES DE DÉMONSTRATION", "setInterval"):
        assert m in HTML, m
    assert "100vh" not in HTML


def test_pas_de_script_externe():
    for src in re.findall(r"<script[^>]*\bsrc=[\"']([^\"']+)", HTML):
        assert not re.match(r"(https?:)?//", src), src
    assert "fonts.googleapis" not in HTML and "cdn" not in HTML.lower()


def test_routes_citees():
    assert "/api/v1/threats" in HTML
    for r in ROUTES:
        assert r in HTML, r


def test_une_seule_ecriture_le_bannissement_2465():
    """Page de lecture, plus une action : bannir une adresse publique 30 jours. Aucune autre écriture."""
    assert HTML.count("method:'POST'") == 1 and 'method: "POST"' not in HTML
    assert "'/api/v1/waf/ban'" in HTML and "duration:'30d'" in HTML
    assert "confirm(" not in re.sub(r"//[^\n]*", "", HTML)                    # confirmation intégrée, jamais celle du navigateur


def test_ni_lorem_ni_secret():
    low = HTML.lower()
    assert "lorem" not in low
    for bad in ("password", "passwd=", "secret", "api_key", "bearer ey"):
        assert bad not in low, bad
