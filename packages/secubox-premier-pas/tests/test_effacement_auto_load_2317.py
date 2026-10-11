# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2317 : l'assistant manuel s'efface devant l'Auto-Load (fichier signé présent), sauf si l'agent a abandonné."""
import shutil
import subprocess
from pathlib import Path

import pytest

SYSTEMD = Path(__file__).resolve().parents[1] / "systemd"
UNITES = ("secubox-premier-pas.service", "secubox-premier-pas-console.service")
OU = ("ConditionPathExists=|!/boot/secubox/autoload/reponses.toml", "ConditionPathExists=|/var/lib/secubox/autoload-agent/abandon.json")


@pytest.mark.parametrize("unite", UNITES)
def test_les_faces_s_effacent_devant_un_fichier_auto_load_sauf_abandon(unite):
    t = (SYSTEMD / unite).read_text(encoding="utf-8")
    assert all(c in t for c in OU)
    assert "ConditionPathExists=!/var/lib/secubox/.premier-pas-fait" in t            # la condition d'origine (box déjà configurée) reste un ET


def _condition(condition: str, tmp: Path) -> bool:
    r = subprocess.run(["systemd-analyze", "condition", condition], capture_output=True, text=True)
    return r.returncode == 0


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze absent")
def test_la_logique_ou_de_systemd_fait_ce_qu_on_dit(tmp_path):
    """Évalué par systemd lui-même : sans fichier -> faces ouvertes ; avec fichier -> fermées ; avec fichier ET abandon -> ouvertes."""
    reponses, abandon = tmp_path / "reponses.toml", tmp_path / "abandon.json"
    def ouvert():
        conds = [f"ConditionPathExists=|!{reponses}", f"ConditionPathExists=|{abandon}"]
        r = subprocess.run(["systemd-analyze", "condition", *conds], capture_output=True, text=True)
        return r.returncode == 0
    assert ouvert()                                   # box ordinaire : pas de fichier Auto-Load
    reponses.write_text("x")
    assert not ouvert()                               # Auto-Load en cours : l'assistant reste fermé
    abandon.write_text("{}")
    assert ouvert()                                   # l'agent a abandonné : l'assistant reprend la main
