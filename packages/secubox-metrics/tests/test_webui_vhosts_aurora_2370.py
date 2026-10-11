# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Page Sites / vhosts au profil Aurora (#2370) : contrat statique, sans navigateur."""

import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "www" / "metrics" / "vhosts.html"
HTML = PAGE.read_text(encoding="utf-8")


def test_licence_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML


def test_postmessage_de_hauteur_et_demo():
    assert "sbxMetricsVue" in HTML
    assert "onglet:'vhosts'" in HTML
    assert "location.origin" in HTML
    assert "demo" in HTML and "DONNÉES DE DÉMONSTRATION" in HTML
    assert "embed" in HTML
    assert "100vh" not in HTML


def test_aucune_ressource_externe():
    srcs = re.findall(r"<script[^>]+src=[\"']([^\"']+)", HTML)
    assert all(not s.startswith(("http:", "https:", "//")) for s in srcs), srcs
    assert not re.search(r"<link[^>]+href=[\"'](https?:)?//", HTML)
    assert "googleapis" not in HTML


def test_routes_de_l_api_citees():
    assert 'const API = "/api/v1/metrics"' in HTML
    for r in ("/vhost-stats", "/cert-status", "/live-hosts", "/vhost-stats/rapport", "/refresh"):
        assert r in HTML, r
    assert "sbx_token" in HTML


def test_actions_post_conservees():
    assert re.search(r'/refresh`, \{method: "POST"\}', HTML)
    assert re.search(r'vhost-stats/rapport\?\$\{p\}`, \{method: "POST"', HTML)


def test_ni_lorem_ni_secret():
    bas = HTML.lower()
    assert "lorem" not in bas
    for motif in ("password", "secret", "api_key", "bearer eyj"):
        assert motif not in bas, motif
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", HTML)


def test_infobulle_visiteur_unique_proxy():
    assert "proxy" in HTML and "Visiteurs ⓘ" in HTML
