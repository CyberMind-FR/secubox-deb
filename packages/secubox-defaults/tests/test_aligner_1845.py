# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-defaults-aligner : /etc/default/secubox nomme CETTE box (#1841, #1845).

Livré à "gk2", le fichier faisait de chaque box une gk2 ; `haproxyctl frontal`
refuse une identité incohérente, et firstboot l'appelle une fois le nom posé.
"""
import os
import subprocess
from pathlib import Path

import pytest

ALIGNER = Path(__file__).resolve().parents[1] / "sbin" / "secubox-defaults-aligner"


@pytest.fixture
def lance(tmp_path):
    defaut = tmp_path / "secubox"
    bin_ = tmp_path / "bin"
    bin_.mkdir()

    def _lance(contenu, domaine=None, hote="secubox-gk9"):
        defaut.write_text(contenu)
        for nom, corps in (("secubox-domaine", f'echo "{domaine}"' if domaine else "exit 1"),
                           ("hostname", f'echo "{hote}"')):
            f = bin_ / nom
            f.write_text("#!/bin/sh\n" + corps + "\n")
            f.chmod(0o755)
        env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", SECUBOX_DEFAULTS_FILE=str(defaut))
        p = subprocess.run(["sh", str(ALIGNER)], env=env, capture_output=True, text=True)
        return p, defaut.read_text()
    return _lance


def test_un_gk2_herite_devient_la_vraie_box(lance):
    p, s = lance('SECUBOX_HOSTNAME="gk2"\nSECUBOX_DOMAIN_SUFFIX="secubox.in"\n', domaine="gk3.secubox.in")
    assert p.returncode == 0 and 'SECUBOX_HOSTNAME="gk3"' in s and 'SECUBOX_DOMAIN_SUFFIX="secubox.in"' in s


def test_gk2_reste_gk2(lance):
    origine = 'SECUBOX_HOSTNAME="gk2"\nSECUBOX_DOMAIN_SUFFIX="secubox.in"\n'
    p, s = lance(origine, domaine="gk2.secubox.in")
    assert p.returncode == 0 and s == origine and p.stdout == ""


def test_sans_secubox_domaine_le_nom_d_hote(lance):
    p, s = lance('SECUBOX_HOSTNAME=""\nSECUBOX_DOMAIN_SUFFIX="secubox.in"\n', domaine=None)
    assert 'SECUBOX_HOSTNAME="gk9"' in s


def test_domaine_douteux_ignore(lance):
    origine = 'SECUBOX_HOSTNAME="gk2"\nSECUBOX_DOMAIN_SUFFIX="secubox.in"\n'
    p, s = lance(origine, domaine="gk3;rm -rf /")
    assert s == origine
