# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 : le routeur ssh se charge même si un autre routeur du paquet est cassé (metrics importe `core`, absent du
paquet installé). Constat banc gk7 : « Router ssh non chargé : No module named 'core' », interrupteur SSH en 404."""
import subprocess
import sys
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
COMMUN = PAQUET.parents[1] / "common"


def test_ssh_se_charge_sans_le_module_core(tmp_path):
    # Copie du paquet SANS le dossier core/ (comme le paquet installé) puis import isolé du routeur ssh.
    subprocess.run(["cp", "-r", str(PAQUET / "api"), str(tmp_path / "api")], check=True)
    code = "import api.routers.ssh as s; print('ok', bool(s.router.routes))"
    r = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True,
                       env={"PYTHONPATH": f"{tmp_path}:{COMMUN}", "PATH": "/usr/bin:/bin"})
    assert r.returncode == 0, r.stderr[-400:]
    assert "ok True" in r.stdout
