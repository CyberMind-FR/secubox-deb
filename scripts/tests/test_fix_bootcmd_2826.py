# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2826 — fix-bootcmd : un script U-Boot livre dans l'image regle le `bootcmd` de la carte (eMMC puis USB), en gardant l'ancien.

Constat : l'environnement U-Boot sauvegarde en SPI chargeait le DTB Ultra et `root=/dev/mmcblk0p2` ; la racine eMMC restait introuvable."""
import struct
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
BOARD = RACINE / "board" / "espressobin-v7"
CMD = (BOARD / "secubox-uboot-env.cmd").read_text()   # renommé #3271 (alias fix-bootcmd.scr dans l'image)
SCR = (BOARD / "secubox-uboot-env.scr").read_bytes()
BUILD = (RACINE / "image" / "build-image.sh").read_text()


def test_l_ancien_bootcmd_est_sauvegarde_avant_d_etre_remplace():
    assert CMD.index('setenv bootcmd_avant "${bootcmd}"') < CMD.index("setenv bootcmd '")


def test_le_nouveau_bootcmd_essaie_l_emmc_puis_l_usb():
    ligne = next(x for x in CMD.splitlines() if x.startswith("setenv bootcmd '"))
    assert ligne.index("mmc dev 1") < ligne.index("load mmc 1:1 ${loadaddr} boot.scr") < ligne.index("usb start") < ligne.index("load usb 0:1 ${loadaddr} boot-usb.scr")
    assert ligne.count("source ${loadaddr}") == 2, "un echec de l'eMMC doit laisser la main au repli USB"


def test_le_script_enregistre_et_dit_comment_revenir_en_arriere():
    assert "saveenv" in CMD and "Revenir en arriere" in CMD
    assert CMD.count("bootcmd_avant") >= 3, "sauvegarde, rappel et mode d'emploi du retour en arriere"


def test_le_binaire_compile_est_un_script_uboot_synchrone_avec_le_source():
    assert struct.unpack(">I", SCR[:4])[0] == 0x27051956 and SCR[30] == 6
    assert CMD.strip().splitlines()[-1].strip().encode() in SCR[64:]


def test_la_construction_livre_le_script_sans_dependre_de_mkimage():
    bloc = BUILD.split("# Script USB (#2816, #2824)", 1)[1].split("# Démonter", 1)[0]
    assert "secubox-uboot-env.scr" in bloc and bloc.index("secubox-uboot-env.scr") < bloc.index("if command -v mkimage")
