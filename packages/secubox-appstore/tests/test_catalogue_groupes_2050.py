# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Le catalogue se génère : aucun groupe ne cite un module absorbé par un autre (#2050).

La construction du paquet exécute gen-appstore-catalog.py ; un groupe qui nomme un paquet devenu composant la
faisait échouer (smb, zigbee, droplet), ce que seule la CI de construction voyait.
"""
import subprocess
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_le_catalogue_se_genere(tmp_path):
    r = subprocess.run([sys.executable, str(PKG / "scripts" / "gen-appstore-catalog.py"), str(tmp_path / "catalog.json")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr or r.stdout
