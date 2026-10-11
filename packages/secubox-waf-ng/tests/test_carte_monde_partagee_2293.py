# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2293 : les nouvelles pages (WAF, Actor Intelligence, DPI) réutilisent la grille éprouvée de la page Actor (corrigée ligne 7), jamais un second dessin du monde."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
ACTOR = (RACINE / "secubox-waf-ng" / "www" / "actor" / "index.html").read_text(encoding="utf-8")
PAGES = {"waf": RACINE / "secubox-waf-ng" / "composants" / "waf" / "www" / "waf" / "vue.html",
         "actor-intelligence": RACINE / "secubox-webos" / "www" / "actor-intelligence" / "index.html",
         "dpi": RACINE / "secubox-dpi" / "www" / "dpi" / "vue.html"}


def grille(texte):
    return re.search(r'var TERRE="([^"]*)"', texte).group(1)


def test_chaque_page_a_la_meme_grille_que_la_page_actor():
    for nom, chemin in PAGES.items():
        assert grille(chemin.read_text(encoding="utf-8")) == grille(ACTOR), nom


def test_aucune_page_ne_dessine_de_continents_a_la_main():
    for nom, chemin in PAGES.items():
        assert "TERRES" not in chemin.read_text(encoding="utf-8"), nom
