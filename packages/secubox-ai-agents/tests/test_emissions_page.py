# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 15 (#4058) : page de l'atelier — sans CDN, SPDX, « Publier » désactivé par défaut, ✗ visibles et réécrivables."""
import re

from conftest import PAQUET

PAGE = (PAQUET / "relais/emissions.html").read_text(encoding="utf-8")


def test_page_sans_cdn():
    assert not re.search(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", PAGE, re.I)
    assert "@import" not in PAGE and "fonts.googleapis" not in PAGE


def test_page_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in PAGE[:400]


def test_publier_desactive_par_defaut():
    m = re.search(r"<button[^>]*id=\"publier\"[^>]*>", PAGE)
    assert m and "disabled" in m.group(0)


def test_trois_colonnes_et_chaine():
    for i in ("hSrc", "hBr", "hVal"):
        assert f'id="{i}"' in PAGE
    for etape in ("Faits", "Évolutions", "Consigne", "Dialogue", "Vérif", "Voix", "Montage"):
        assert etape in PAGE
    assert "<audio" in PAGE and "chronologie" in PAGE


def test_retirees_visibles_et_reecriture():
    assert "Réécrire cette réplique" in PAGE and "retiree" in PAGE and "motifs" in PAGE


def test_aucun_innerhtml_de_donnees():
    assert "innerHTML" not in PAGE                       # tout texte de gk2 ou du LLM passe par textContent
