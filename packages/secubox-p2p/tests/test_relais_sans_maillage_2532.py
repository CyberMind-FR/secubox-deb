# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2532 — `secubox-relais-maillage synchroniser` sur une box SANS maillage ne doit pas échouer.

`pairs="$(pairs_32)"` : `wg show wg-mesh` échoue (pas d'interface) et, sous set -e/pipefail, tuait le script AVANT la garde « aucun pair à
relayer » qui retourne 0 : l'unité horaire restait en échec sur toute box neuve."""
import os
import subprocess
from pathlib import Path

import pytest

# Le script refuse de tourner hors root (garde de son en-tête) : ces tests se lancent en root.
pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="secubox-relais-maillage exige root")

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-relais-maillage"


def _lance(tmp_path):
    (tmp_path / "bin").mkdir()
    wg = tmp_path / "bin" / "wg"
    wg.write_text("#!/bin/sh\necho 'Unable to access interface: No such device' >&2\nexit 1\n")
    wg.chmod(0o755)
    env = dict(os.environ, PATH=f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    return subprocess.run(["bash", str(SCRIPT), "synchroniser"], env=env, capture_output=True, text=True, timeout=60)


def test_sans_interface_wg_mesh_la_synchronisation_reussit(tmp_path):
    p = _lance(tmp_path)
    assert p.returncode == 0, f"rc={p.returncode}\n{p.stdout}\n{p.stderr}"


def test_elle_dit_qu_il_n_y_a_aucun_pair(tmp_path):
    assert "aucun pair" in _lance(tmp_path).stdout
