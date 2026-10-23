# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""`common/` et l'API du composant turn sur le chemin d'import (#3060)."""
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
for p in (RACINE / "common", RACINE / "packages" / "secubox-jitsi" / "composants" / "turn"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:  # noqa: SIM105 — sans fastapi (CI minimale) il n'y a pas d'application à armer
    from secubox_core.testing import active_mode_tableau_de_bord as _sbx_tdb

    _sbx_tdb()
except ImportError:
    pass
