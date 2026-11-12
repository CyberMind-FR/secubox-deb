# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3679 : l'ACL par défaut posée pour secubox-live ne doit jamais retirer l'écriture de groupe qu'un producteur demande."""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-live-acl"


def test_defaut_du_groupe_et_masque_en_rwx_et_journal_retabli():
    s = SCRIPT.read_text(encoding="utf-8")
    assert re.search(r'setfacl -d -m u:secubox-live:r,g::rwx,m::rwx "\$d"', s)
    assert 'setfacl -m g::rw,m::rw "$f"' in s and "f=/var/log/secubox/waf/waf-threats.log" in s


@pytest.mark.skipif(shutil.which("setfacl") is None or shutil.which("getfacl") is None, reason="acl absent")
def test_fichier_0660_garde_l_ecriture_0640_reste_en_lecture(tmp_path):
    d = tmp_path / "waf"
    d.mkdir()
    d.chmod(0o750)
    moi = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()
    r = subprocess.run(["setfacl", "-d", "-m", f"u:{moi}:r,g::rwx,m::rwx", str(d)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("système de fichiers sans ACL")
    ancien = os.umask(0)
    try:
        for nom, mode in (("f660", 0o660), ("f640", 0o640)):
            os.close(os.open(d / nom, os.O_CREAT | os.O_WRONLY, mode))
    finally:
        os.umask(ancien)

    def effectif(nom):
        sortie = subprocess.run(["getfacl", "-p", str(d / nom)], capture_output=True, text=True, check=True).stdout
        masque = re.search(r"^mask::(\S+)", sortie, re.M).group(1)
        return masque

    assert effectif("f660") == "rw-"
    assert effectif("f640") == "r--"
