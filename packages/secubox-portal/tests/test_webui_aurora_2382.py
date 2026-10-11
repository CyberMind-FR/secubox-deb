# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Page /portal/ au profil Aurora (#2382) : contrôles statiques, sans navigateur."""

import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
PAGE = RACINE / "www" / "portal" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML


def test_hauteur_demo_embed():
    assert "sbxVue" in HTML and "onglet:'portal'" in HTML
    assert "demo" in HTML and "DONNÉES DE DÉMONSTRATION" in HTML
    assert "embed" in HTML
    assert "100vh" not in HTML


def test_aucun_script_externe():
    assert not re.search(r"<script[^>]+src=", HTML)
    sans = re.sub(r"<!--.*?-->", "", HTML, flags=re.S).replace("http://www.w3.org", "")
    assert not re.search(r"https?://", sans)


def test_ni_lorem_ni_secret():
    bas = HTML.lower()
    assert "lorem" not in bas
    for mot in ("password", "passwd", "api_key", "secret"):
        assert mot not in bas


def test_pas_de_dialogues_navigateur():
    assert not re.search(r"\b(confirm|alert|prompt)\(", HTML)


def test_routes_citees():
    for r in ("/api/v1/metrics/health/summary", "/api/v1/metrics/cert-status",
              "/api/v1/metrics/live-hosts", "/api/v1/metrics/visitor-origin",
              "/api/v1/cookie-audit/summary", "/api/v1/portal/verify",
              "/api/v1/portal/status", "/api/v1/portal/summary", "/api/v1/portal/sessions"):
        assert r in HTML, r
    assert "sbx_token" in HTML


def test_lecture_seule_comme_l_ancienne_page():
    # l'ancienne page n'émettait aucune écriture : on n'en invente pas
    assert not re.search(r"method\s*:\s*['\"](POST|DELETE|PUT|PATCH)", HTML)


def test_login_html_intact():
    r = subprocess.run(["git", "diff", "--quiet", "--", "packages/secubox-portal/www/login.html"],
                       cwd=RACINE.parents[1])
    assert r.returncode == 0
