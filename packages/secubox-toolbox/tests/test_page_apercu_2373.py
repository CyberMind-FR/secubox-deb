# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Onglet « Vue d'ensemble » du Toolbox au profil Aurora (apercu.html) — contrôles statiques (#2373)."""
import pathlib
import re

PAGE = pathlib.Path(__file__).resolve().parent.parent / "www" / "toolbox" / "apercu.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx_et_marqueurs():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert "sbxToolboxVue" in SRC and "onglet:'apercu'" in SRC
    assert "demo" in SRC and "DONNÉES DE DÉMONSTRATION" in SRC
    assert "sbx_token" in SRC and "?embed" in SRC.replace("q.get('embed')", "?embed") or "embed" in SRC


def test_aucune_ressource_externe():
    assert not re.search(r"<script[^>]+src=", SRC, re.I)
    assert not re.search(r"<link[^>]+href=\"https?:", SRC, re.I)
    assert "min-height:100vh" not in SRC


def test_pas_de_lorem_ni_secret():
    low = SRC.lower()
    assert "lorem" not in low
    assert not re.search(r"(password|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]", low)


def test_pas_de_dialogue_natif():
    assert not re.search(r"(?<![\w.])(confirm|alert)\(", SRC)


def test_routes_citees():
    for r in ("admin/metrics", "admin/config", "admin/clients/rich", "admin/ad-stats",
              "admin/tor/state", "admin/sentinel/stats", "admin/sentinel/verdicts",
              "netstats/summary", "netstats/series", "/api/v1/toolbox/", "/api/v1/hub/"):
        assert r in SRC, r


def test_lecture_seule_comme_l_ancien_onglet():
    """L'ancien panneau overview n'avait aucun POST : la page n'en émet pas non plus."""
    assert "POST" not in re.sub(r"<!--.*?-->", "", SRC, flags=re.S).replace("(POST)", "")
    assert "method:" not in SRC
