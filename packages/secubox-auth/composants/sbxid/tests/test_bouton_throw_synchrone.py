# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Un throw synchrone d'une action de bouton finit dans le .catch (pages d'accès)."""
from pathlib import Path

import pytest

PAGES = [Path(__file__).parent.parent / "acces" / "www" / "acces" / n for n in ("micro.html", "index.html")]


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_action_executee_dans_la_chaine_de_promesses(page):
    texte = page.read_text()
    assert "Promise.resolve().then(action).then(rafraichis)" in texte
    assert "Promise.resolve(action())" not in texte      # throw synchrone : onclick, hors .catch
