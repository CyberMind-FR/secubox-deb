# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2212 : la matrice docs/SBXOS_ADMIN_UI_MAP.md suit packages/secubox-hub/espaces.json et les menu.d (même principe que le test de dérive des thèmes)."""
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]


def test_la_matrice_n_a_pas_derive():
    r = subprocess.run([sys.executable, str(RACINE / "scripts" / "generate-admin-ui-map.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
