# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Par défaut, les tests de l'API s'exécutent sur une box « libre » (marqueur abonnement-libre, #3338) : la règle
d'abonnement, fail-closed, a ses propres tests (test_boutique_abonnement_3338.py, qui repose sa propre racine)."""
import pytest


@pytest.fixture(autouse=True)
def _box_libre(monkeypatch, tmp_path_factory):
    r = tmp_path_factory.mktemp("box-libre")
    (r / "etc/secubox").mkdir(parents=True)
    (r / "etc/secubox/abonnement-libre").write_text("")
    monkeypatch.setenv("APPSTORE_RACINE", str(r))
