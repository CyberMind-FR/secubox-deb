# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""zigbee-restore n'accepte qu'un NOM d'instantané (#1785) : il tourne en root
par sudo avec tout argument, et un chemin faisait copier par root un
répertoire quelconque dans les données de zigbee2mqtt."""
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "zigbee-restore"


def _lancer(tmp_path, ts):
    env = dict(os.environ, SECUBOX_ZIGBEE_BACKUP_DIR=str(tmp_path / "bk"))
    return subprocess.run(["bash", str(SCRIPT), ts], env=env, capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize("ts", ["../evil", "20260930T101010Z/../../evil", "x;id", "-rf", ""])
def test_nom_hors_grammaire_refuse(tmp_path, ts):
    (tmp_path / "evil").mkdir()
    (tmp_path / "evil" / "database.db").write_text("pwn")
    r = _lancer(tmp_path, ts)
    assert r.returncode != 0
    assert ("instantané refusé" in r.stderr) or (ts == "" and "missing" in r.stderr)


@pytest.mark.parametrize("ts", ["20260930T101010Z", "pre-restore-20260930T101010Z"])
def test_nom_valide_passe_la_garde(tmp_path, ts):
    r = _lancer(tmp_path, ts)
    assert "instantané refusé" not in r.stderr


def test_sudoers_backup_sans_argument():
    s = (SCRIPT.parents[1] / "sudoers.d" / "secubox-zigbee").read_text()
    assert '/usr/sbin/zigbee-backup ""' in s
