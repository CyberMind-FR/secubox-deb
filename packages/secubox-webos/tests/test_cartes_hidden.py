# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Les cartes du Hall qui masquent par `hidden` honorent l'attribut (#2146).

Un `display:block` / `display:grid` d'auteur l'emporte sur `[hidden]{display:none}` du navigateur : l'élément masqué reste
affiché. Constaté sur la carte « Coffre », puis, en les passant toutes dans Chromium, sur `metablog` (`#une`, `#une-sans`)."""
import re
from pathlib import Path

CARTES = Path(__file__).resolve().parents[1] / "www" / "hall" / "cardlets"
# Cartes dont un élément `hidden` restait AFFICHÉ, constaté dans Chromium (balayage de toutes les cartes, états vide et 404).
# Les autres cartes passent ce balayage sans la règle : on ne la leur ajoute pas à l'aveugle (`!important` masquerait un élément
# qu'un script affiche par `style.display` en laissant `hidden`).
CORRIGEES = ["coffre.html", "metablog.html"]


def test_les_cartes_corrigees_forcent_l_attribut_hidden():
    for nom in CORRIGEES:
        t = (CARTES / nom).read_text(encoding="utf-8")
        assert "[hidden]{display:none!important}" in t.replace(" ", ""), f"{nom} : [hidden] n'est pas forcé"
