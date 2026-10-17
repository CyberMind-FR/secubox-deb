# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""La page identite ne cite pas un vrai compte comme exemple (#2881)."""
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants/sbxid/www/identite/index.html"


def test_aucun_vrai_pseudo_dans_la_page():
    assert "cedre83" not in PAGE.read_text()


def test_exemple_du_champ_pseudo_neutre():
    assert 'id="np-pseudo"' in PAGE.read_text()
    assert 'placeholder="pseudo"' in PAGE.read_text()
