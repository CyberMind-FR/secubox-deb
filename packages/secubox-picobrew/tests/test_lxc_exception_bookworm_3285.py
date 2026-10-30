# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Exception écrite à #3285 (tous les LXC en dernière Debian stable) : ce
conteneur reste en bookworm pour une raison vérifiée (picobrew_pico épingle eventlet==0.36.1, Python 3.13 seulement à partir d'eventlet 0.38.0).
Le test fige l'exception : elle reste explicite, motivée et surchargeable par
SECUBOX_DEBIAN_SUITE ; la lever, c'est retirer ce test avec elle."""
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin/picobrewctl"


def test_exception_bookworm_explicite_et_motivee():
    texte = SCRIPT.read_text(encoding="utf-8")
    assert "EXCEPTION À #3285" in texte
    assert "eventlet==0.36.1" in texte
    code = [ligne for ligne in texte.splitlines() if "bookworm" in ligne and not ligne.lstrip().startswith("#")]
    assert code == ['    local suite="${SECUBOX_DEBIAN_SUITE:-bookworm}"'], code
