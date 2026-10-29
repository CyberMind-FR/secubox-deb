# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from pathlib import Path

UNITE = Path(__file__).resolve().parent.parent / "systemd" / "secubox-pilotage.service"


def test_unite_pilotage_memoire_bornee():
    lignes = {ligne.strip() for ligne in UNITE.read_text(encoding="utf-8").splitlines()}
    assert "MemoryMax=128M" in lignes and "MemoryHigh=96M" in lignes
