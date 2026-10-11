# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Page /metrics/ au profil Aurora (#2370) : contrôles statiques, sans navigateur."""

import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "www" / "metrics" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML


def test_message_de_hauteur_et_demo():
    assert "sbxMetricsVue" in HTML
    assert "onglet:'index'" in HTML
    assert "demo" in HTML and "DONNÉES DE DÉMONSTRATION" in HTML
    assert "embed" in HTML


def test_aucun_script_externe():
    # seul le menu latéral commun est chargé, injecté par le script (hors embed)
    assert not re.search(r"<script[^>]+src=", HTML)
    assert not re.search(r"https?://", re.sub(r"<!--.*?-->", "", HTML, flags=re.S).replace("http://www.w3.org", ""))


def test_ni_lorem_ni_secret():
    bas = HTML.lower()
    assert "lorem" not in bas
    for mot in ("password", "passwd", "api_key", "secret"):
        assert mot not in bas


def test_routes_citees():
    for r in ("/overview", "/health/summary", "/memory/history", "/connections",
              "/waf_stats", "/waf/campaigns", "/cert-status", "/live-hosts"):
        assert re.search(r"api\('" + re.escape(r), HTML), r
    assert "/api/v1/metrics" in HTML
    assert "sbx_token" in HTML


def test_pas_de_min_height_100vh_et_lecture_seule():
    assert "100vh" not in HTML
    assert "method:'POST'" not in HTML and 'method:"POST"' not in HTML


def test_lien_vers_sites_et_rafraichissement():
    assert "/metrics/vhosts.html" in HTML
    assert "15000" in HTML
