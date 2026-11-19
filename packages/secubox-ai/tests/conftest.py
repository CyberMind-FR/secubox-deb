# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests de secubox-ai (#3583). common/ (secubox_core) et le paquet sont ajoutés au chemin ; le paquet est
importé sous le nom `api` : lancer ces tests seuls (collision des paquets `api`, cf. pytest.ini)."""
import sys
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
RACINE = PAQUET.parents[1]
for chemin in (RACINE / "common", PAQUET):
    if str(chemin) not in sys.path:
        sys.path.insert(0, str(chemin))
