# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Cartes du monde des pages Metrics (#2390) : contrôles statiques, sans navigateur."""

import re
from pathlib import Path

WWW = Path(__file__).resolve().parents[1] / "www" / "metrics"
VUE_WAF = Path(__file__).resolve().parents[2] / "secubox-waf-ng" / "composants" / "waf" / "www" / "waf" / "vue.html"
PAGES = {n: (WWW / n).read_text(encoding="utf-8") for n in ("index.html", "vhosts.html")}


def test_grille_identique_a_la_vue_waf():
    # même grille 60 × 120 et mêmes centres de pays que la vue d'ensemble du WAF
    if VUE_WAF.exists():
        ref = VUE_WAF.read_text(encoding="utf-8")
        terre = re.search(r'var TERRE="[^"]+"', ref).group(0)
        centre = re.search(r'var CENTRE=\{.*?\};', ref).group(0)
    else:
        terre = centre = None
    for nom, html in PAGES.items():
        assert 'viewBox="0 0 120 60"' in html, nom
        assert "var TERRE=" in html and "var CENTRE=" in html, nom
        if terre:
            assert terre in html and centre in html, nom


def test_routes_de_pays_citees():
    assert "api('/vhost-stats?periode=semaine')" in PAGES["index.html"]
    assert "waf_stats" in PAGES["index.html"]
    v = PAGES["vhosts.html"]
    assert "api('/vhost-stats?periode='" in v or "/vhost-stats" in v
    assert "d.pays" in v and "v.pays" in v


def test_panneaux_et_sans_mesure():
    i = PAGES["index.html"]
    assert "Origine des attaques" in i and "Origine des visiteurs" in i
    assert "#ff4d5e" in i and "#29b6f6" in i
    assert "<div class=\"vide\">— " in i
    v = PAGES["vhosts.html"]
    assert "Origine des visites" in v and "mondeD" in v


def test_aucun_script_externe():
    for nom, html in PAGES.items():
        assert not re.search(r"<script[^>]+src=\s*[\"']https?:", html), nom
        assert 'const API = ' in html or "const API = " in html or "var API" in html or "API = " in html, nom
