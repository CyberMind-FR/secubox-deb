# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Exception écrite à #3285 (tous les LXC en dernière Debian stable) : ce
conteneur reste en bookworm pour une raison vérifiée (venv figé sur Python 3.11, ctranslate2==4.4.0 sans roue Python 3.13).
Le test fige l'exception : elle reste explicite, motivée et surchargeable par
SECUBOX_DEBIAN_SUITE ; la lever, c'est retirer ce test avec elle."""
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "lxc/install-lxc.sh"


def test_exception_bookworm_explicite_et_motivee():
    texte = SCRIPT.read_text(encoding="utf-8")
    assert "EXCEPTION À #3285" in texte
    assert "ctranslate2==4.4.0" in texte
    code = [ligne for ligne in texte.splitlines() if "bookworm" in ligne and not ligne.lstrip().startswith("#")]
    assert code == ['readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"'], code
