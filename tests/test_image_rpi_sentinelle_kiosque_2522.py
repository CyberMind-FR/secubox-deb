# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Image RPi400 (ref #2522) : le kiosque doit démarrer au premier boot.

secubox-console livre un drop-in qui conditionne secubox-kiosk.service à /var/lib/secubox/.kiosk-enabled (#2332). Le constructeur d'image
écrivait l'unité et boot-mode=kiosk mais pas cette sentinelle : l'unité était ignorée à chaque démarrage."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
SCRIPT = (RACINE / "image" / "build-rpi-usb.sh").read_text()
DROPIN = (RACINE / "packages" / "secubox-console" / "debian" / "dropins" / "kiosk-sentinelle.conf").read_text()


def test_le_dropin_exige_bien_cette_sentinelle():
    """Garde-fou : si le drop-in change de sentinelle, ce test doit casser avant l'image."""
    assert re.search(r"^ConditionPathExists=(/var/lib/secubox/\.kiosk-enabled)$", DROPIN, re.M)


def test_le_constructeur_pose_la_sentinelle_exigee_par_le_dropin():
    m = re.search(r"^ConditionPathExists=(\S+)$", DROPIN, re.M)
    chemin = m.group(1)
    assert f'"${{ROOTFS}}{chemin}"' in SCRIPT, "build-rpi-usb.sh ne crée pas la sentinelle du kiosque"


def test_l_assertion_de_build_verifie_la_sentinelle():
    bloc = SCRIPT[SCRIPT.index("for _f in \\"):SCRIPT.index("for _f in \\") + 700]
    assert ".kiosk-enabled" in bloc
