# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2532 — secubox-bootmenu (image RPi) ne doit jamais échouer ni refaire un état déjà appliqué.

Il tourne Before=sysinit.target : `systemctl set-default` y échouait (sortie 1, unité « failed », système « degraded »)."""
import re
from pathlib import Path

TEXTE = (Path(__file__).resolve().parents[1] / "image" / "build-rpi-usb.sh").read_text()
DEBUT = TEXTE.index("<<'BOOTMENU'")
MENU = TEXTE[DEBUT:TEXTE.index("\nBOOTMENU\n", DEBUT)]


def test_aucun_set_default_n_est_fatal():
    lignes = [l for l in MENU.splitlines() if "systemctl set-default" in l]
    assert lignes
    for l in lignes:
        assert "|| true" in l, l


def test_le_script_se_termine_toujours_par_zero():
    assert MENU.rstrip().splitlines()[-1].strip() == "exit 0"


def test_un_mode_deja_applique_n_est_pas_reapplique():
    assert "systemctl get-default" in MENU
