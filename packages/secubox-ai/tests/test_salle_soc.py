# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet Salle de /ai/ (2.2.0, SBX-SOC porté du POC gk0) : premier onglet et onglet par défaut, routes du module
seulement, aucune ressource externe, aucune animation sous prefers-reduced-motion, donnée absente dite."""
import re
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
PAGE = PAQUET / "www" / "ai" / "index.html"


@pytest.fixture(scope="module")
def html():
    return PAGE.read_text(encoding="utf-8")


def _script(html):
    blocs = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert len(blocs) == 1
    return blocs[0]


def _fonction(source, nom):
    debut = source.index(f"function {nom}(")
    profondeur, i = 0, source.index("{", debut)
    while True:
        profondeur += {"{": 1, "}": -1}.get(source[i], 0)
        if profondeur == 0:
            return source[debut:i + 1]
        i += 1


def test_salle_premier_onglet_et_par_defaut(html):
    declares = re.search(r"var ONGLETS\s*=\s*\[(.*?)\];", html, re.S).group(1)
    onglets = re.findall(r"\['([a-z]+)',\s*'[^']+'\]", declares)
    assert onglets[0] == "salle" and "essai" in onglets
    assert re.findall(r'<section data-o="([a-z]+)"', html)[0] == "salle"
    assert "? q.get('onglet') : 'salle');" in html
    assert "if (n === 'salle') chargerSalle();" in html


def test_salle_lit_les_routes_du_module(html):
    corps = _fonction(_script(html), "chargerSalle")
    for route in ("'/menaces/releve'", "'/menaces/series?fenetre='", "'/actions?limite=50'", "'/veille/etat'"):
        assert route in corps, route
    assert "chargerEtat()" in corps                     # état du moteur : la lecture existante de /status
    assert "/menaces/gestes" not in html                # route du POC absente du module


def test_salle_rafraichie_seulement_visible_et_pas_trop_souvent(html):
    s = _script(html)
    assert "S_PERIODE_S = 30" in s
    assert re.search(r"section\[data-o=salle\]'\); if \(s && !s\.hidden && !document\.hidden\) chargerSalle\(\); \}, "
                     r"S_PERIODE_S \* 1000\)", s)


def test_aucune_url_externe(html):
    hotes = set(re.findall(r"https?://([A-Za-z0-9.-]+)", html))
    assert hotes <= {"www.w3.org"}, hotes            # espace de noms SVG seulement, jamais chargé
    assert not re.search(r"<(script|link|img)[^>]+(src|href)=\"(https?:)?//", html)
    assert "@import" not in html and "fonts.googleapis" not in html


def test_mouvement_reduit_sans_animation(html):
    bloc = re.search(r"@media \(prefers-reduced-motion:reduce\)\{(.*?)\}\}", html, re.S)
    assert bloc
    assert ".sradar .sbal{animation:none" in bloc.group(1)
    assert "section[data-o=salle] *" in bloc.group(1) and "animation:none!important" in bloc.group(1)


def test_donnee_absente_dite(html):
    s = _script(html)
    assert "S_ND = 'relevé indisponible'" in s
    # le mode SADE vient de /veille/etat ; absent = relevé indisponible, jamais un texte en dur
    assert "v.sade_mode" in _fonction(s, "sKpis")
    assert "aucune route ne le relève" not in s


def test_defauts_du_poc_corriges(html):
    assert re.search(r"\.sgr\{[^}]*white-space:nowrap", html)                 # « MOYENNE » sur une ligne
    assert ".sinc col.c-g{width:88px}" in html and "colgroup" in _fonction(_script(html), "sIncidents")
    radar = _fonction(_script(html), "sRadar")
    assert "R_MIN" in radar and "Math.log(1 + p.n)" in radar                  # échelle log + rayon minimal


def test_action_reelle_tiree_des_actions(html):
    corps = _fonction(_script(html), "sReel")
    assert "sAction(al.client_ip)" in corps and "fin_gk2" in corps
    assert "'observé'" in corps
