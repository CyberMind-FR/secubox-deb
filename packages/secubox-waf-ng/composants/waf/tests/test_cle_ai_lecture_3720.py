# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(COMPOSANT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
WAFCTL = COMPOSANT / "scripts" / "wafctl"
POSTINST = COMPOSANT.parents[1] / "debian" / "postinst"


def test_postinst_cree_le_dossier_ai_lecture():
    t = POSTINST.read_text()
    d = "/etc/secubox-comptes-service/ai-lecture"
    assert f"mkdir -p {d}" in t and f"chown root:root {d}" in t and f"chmod 0755 {d}" in t


def test_wafctl_cle_ai_lecture(tmp_path):
    from test_gestes_ia_3716 import _pub_pem
    from secubox_core import compte_service as cs
    t = WAFCTL.read_text()
    assert "cle-ai-lecture) shift; cmd_cle_ai_lecture" in t
    assert "cle-ai-lecture generer" not in t   # la clé privée naît sur gk3
    if not shutil.which("openssl") or not shutil.which("jq"):
        pytest.skip("openssl et jq requis")
    racine, audit = tmp_path / "comptes", tmp_path / "audit.log"
    copie = tmp_path / "wafctl"
    copie.write_text(t.replace('CLES_RACINE="/etc/secubox-comptes-service"', f'CLES_RACINE="{racine}"')
                      .replace('AUDIT_LOG="/var/log/secubox/audit.log"', f'AUDIT_LOG="{audit}"'))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "install").write_text('#!/bin/bash\nargs=()\nwhile [ "$#" -gt 0 ]; do\n  case "$1" in -o|-g) shift 2 ;; '
                                  '*) args+=("$1"); shift ;; esac\ndone\nexec /usr/bin/install "${args[@]}"\n')
    (bin_ / "install").chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}

    def lancer(*args):
        return subprocess.run(["bash", str(copie), "cle-ai-lecture", *args], check=False, timeout=30,
                              capture_output=True, text=True, env=env)
    f1, pem1 = _pub_pem(tmp_path, "un.pub")
    r = lancer("ajouter", str(f1))
    assert r.returncode == 0, r.stderr
    kid = cs.empreinte(pem1)
    assert [p.name for p in (racine / "ai-lecture").iterdir()] == [f"{kid}.pub"]
    assert not (racine / "ai-ban").exists()
    assert json.loads(audit.read_text().splitlines()[-1])["action"] == "cle-ai-lecture-ajout"
    assert kid in lancer("lister").stdout
    assert lancer("retirer", kid).returncode == 0
    assert list((racine / "ai-lecture").iterdir()) == []
    assert json.loads(audit.read_text().splitlines()[-1])["action"] == "cle-ai-lecture-retrait"
