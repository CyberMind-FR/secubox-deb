# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Les trois profils passent `verify-profile.sh` (#2146).

La construction des images refuse un profil dont un module n'est pas dans le working-set de la carte de référence. La refonte des
profils y ajoutait des modules absents d'un instantané du 21 août : les SEPT images de la release alpha.10 ont échoué à cette étape,
après trois heures de construction des paquets. Ce test attrape la même erreur au premier push."""
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("profil", ["lite", "isp", "full"])
def test_le_profil_passe_le_controle_de_la_construction_des_images(profil):
    r = subprocess.run(["bash", str(RACINE / "scripts" / "verify-profile.sh"), profil], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_soc_agent_n_est_dans_aucun_profil():
    """Il pousse vers une passerelle SOC décommissionnée et accepte des commandes à distance : jamais par défaut."""
    for p in ("lite", "isp", "full"):
        t = (RACINE / "packages" / f"secubox-{p}" / "debian" / "control").read_text()
        dep = t.split("\nDepends:")[1].split("\nRecommends:")[0]
        assert "secubox-soc-agent" not in "\n".join(l for l in dep.splitlines() if not l.strip().startswith("#"))
