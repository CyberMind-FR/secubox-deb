# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Cartes vivantes (#3945) : composant partagé chargé par la page, facultatif, données réelles seulement. Comportement du
composant : secubox-hub/tests/test_pouls_3945.py."""
import re
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
CHARGE = 'j.src = "/shared/pouls.js"; j.onload = vivre'


@pytest.mark.parametrize("page", ['www/soc/index.html'])
def test_composant_facultatif_et_donnees_reelles(page):
    src = (ICI / page).read_text(encoding="utf-8")
    assert src.count(CHARGE) == 1 and not re.search(r"<script[^>]+src=", src)
    assert re.search(r"if ?\(!P ?\|\| ?!VIE\) ?\{? ?return;", src)                  # absent : la page reste fixe
    assert re.search(r"(?:d\.demo|DEMO) ?\? ?\[r\] ?: ?P\.memoire\(", src)           # démonstration jamais gardée
    for cle in ['soc-alertes']:
        assert f"'{cle}" in src or f'"{cle}' in src
    assert "vivre();" in src and "P.bouton(" in src
