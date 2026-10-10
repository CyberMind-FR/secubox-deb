# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2285 : `scripts/verify-profile.sh` est la porte des images (release.yml). Les trois profils doivent la passer AVANT un tag : le jour où l'agent Auto-Load est entré dans lite
sans entrer dans le working-set, sept images disque ont échoué sur le tag alpha.11 alors que la suite de tests était verte."""
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("profil", ["lite", "isp", "full"])
def test_le_profil_passe_la_porte_des_images(profil):
    r = subprocess.run(["bash", str(RACINE / "scripts" / "verify-profile.sh"), profil], capture_output=True, text=True, timeout=120, cwd=RACINE)
    assert r.returncode == 0, r.stdout + r.stderr


def test_l_agent_auto_load_est_au_working_set_avec_sa_raison():
    lignes = (RACINE / "image" / "profiles" / "working-set.gk2.txt").read_text().splitlines()
    i = [n for n, l in enumerate(lignes) if l.strip() == "autoload-agent"]
    assert i, "autoload-agent absent du working-set"
    avant = "\n".join(lignes[max(0, i[0] - 7):i[0]])
    assert "AJOUT MANUEL" in avant and "#2280" in avant            # une entrée manuelle dit pourquoi elle est là, juste au-dessus
