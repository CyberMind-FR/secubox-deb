# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 : l'écran de changement imposé offre « Plus tard » (POST /api/v1/auth/plus-tard avec le setup_token)."""
from pathlib import Path

PAGE = (Path(__file__).resolve().parents[1] / "www" / "login.html").read_text()


def test_bouton_plus_tard_dans_l_ecran_de_changement():
    i = PAGE.index('<form id="setup-form"')
    assert 'id="btn-plus-tard"' in PAGE[i:PAGE.index("</form>", i)]


def test_plus_tard_echange_le_setup_token_contre_une_session():
    i = PAGE.index("function handlePlusTard")
    bloc = PAGE[i:PAGE.index("\n}\n", i)]
    assert "/api/v1/auth/plus-tard" in bloc and "'Bearer ' + jeton" in bloc and "finalizeToken" in bloc
    assert "_setupToken = ''" in bloc                      # jeton à usage unique : oublié aussitôt
    assert "$('btn-plus-tard').addEventListener('click', handlePlusTard)" in PAGE
