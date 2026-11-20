# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — échelle SADE : projection du score (priority d'actord) sur bandes et phases."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import echelle  # noqa: E402


@pytest.mark.parametrize("s,b", [(0, "observer"), (19, "observer"), (20, "reactive"), (59, "reactive"),
                                 (60, "contenir"), (79, "contenir"), (80, "usager"), (94, "usager"),
                                 (95, "incident"), (100, "incident")])
def test_bornes(s, b):
    assert echelle.bande(s) == b


@pytest.mark.parametrize("s", [None, "", "82", -1, 101, 3.5, True, False])
def test_score_invalide_est_inconnu(s):
    assert echelle.bande(s) == "inconnu"


def test_phase_et_validation():
    assert [echelle.phase(b) for b in ("observer", "reactive", "contenir", "usager", "incident", "inconnu")] \
        == [1, 2, 3, 3, 3, 0]
    assert echelle.exige_validation("incident") and not echelle.exige_validation("usager")


def test_bandes_defaut_structure():
    assert echelle.BANDES_DEFAUT == ((0, "observer"), (20, "reactive"), (60, "contenir"),
                                     (80, "usager"), (95, "incident"))
