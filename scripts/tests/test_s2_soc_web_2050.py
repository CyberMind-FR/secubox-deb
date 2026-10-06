# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 S2 : secubox-soc-web (décommissionné depuis #1323, jamais déployé) quitte le dépôt ; secubox-soc garde
Conflicts/Replaces pour retirer l'ancien paquet des boxes qui l'ont encore."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]


def test_le_paquet_soc_web_n_est_plus_dans_le_depot():
    assert not (RACINE / "packages/secubox-soc-web").exists()


def test_soc_retire_encore_l_ancien_paquet_des_boxes():
    c = (RACINE / "packages/secubox-soc/debian/control").read_text()
    assert re.search(r"(?m)^Conflicts:.*secubox-soc-web", c)
    assert re.search(r"(?m)^Replaces:.*secubox-soc-web", c)


def test_arbre_et_ci_ne_construisent_ni_ne_recommandent_soc_web():
    arbre = (RACINE / "packages/secubox-meta/arbre.yaml").read_text()
    assert not re.search(r"(?m)^\s+- secubox-soc-web\b", arbre)
    for wf in (".github/workflows/build-packages.yml", ".gitea/workflows/build-packages.yml"):
        assert "matrix.package == 'secubox-soc-web'" not in (RACINE / wf).read_text(), wf
