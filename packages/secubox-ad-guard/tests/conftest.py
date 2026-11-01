# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parents[1] / "common"))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _administrateur_de_test(monkeypatch):
    """Les tests d'API surchargent `require_lecture` par `{"sub": "admin"}` : ce porteur-là est l'administrateur réel
    (sans registre des comptes) ; tout autre `sub` (« lecteur », « usager ») ne l'est pas (#3374, garde nominative)."""
    try:
        from api import dnstv_routes as r
    except Exception:                                   # noqa: BLE001 — paquet non importable dans ce test
        return
    monkeypatch.setattr(r, "est_admin_reel", lambda p: isinstance(p, dict) and p.get("sub") == "admin")
