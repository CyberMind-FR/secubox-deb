# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Les pages du Coffre honorent l'attribut `hidden` (#2146).

`section{display:flex}` et `.kpis{display:flex}` l'emportent sur la règle `[hidden]{display:none}` du navigateur : une section
masquée par le script restait AFFICHÉE. Dans « Mon coffre » ouvert, le formulaire « Créer ma serrure » (masqué) passait devant
le contenu du compartiment, et dans le cadre de 380 px du Hall on ne voyait que lui — « il n'affiche rien »."""
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
PAGES = [
    RACINE / "secubox-vault" / "www" / "coffre" / "index.html",
    RACINE / "secubox-vault" / "www" / "vault" / "index.html",
    RACINE / "secubox-webos" / "www" / "hall" / "cardlets" / "coffre.html",
]


def test_chaque_page_force_l_attribut_hidden():
    for p in PAGES:
        t = p.read_text(encoding="utf-8")
        assert "[hidden]{display:none!important}" in t.replace(" ", ""), f"{p.name} : [hidden] n'est pas forcé"


def test_mon_coffre_se_remet_a_jour_apres_la_reconnexion():
    """La page ne lisait l'état du Coffre qu'UNE fois, au chargement : après la reconnexion qui l'ouvre, le cadre du Hall
    restait sur « scellé » jusqu'à un rechargement. Elle relit l'état tant qu'elle n'est pas ouverte, et au retour sur l'onglet."""
    t = (RACINE / "secubox-vault" / "www" / "coffre" / "index.html").read_text(encoding="utf-8")
    assert "async function rafraichit()" in t
    assert "setInterval(rafraichit" in t and "visibilitychange" in t
    corps = t.split("async function rafraichit()")[1].split("\n  }\n")[0]
    assert "if (OUV" in corps, "une fois ouvert, plus de relecture (le geste de la personne n'est pas interrompu)"
