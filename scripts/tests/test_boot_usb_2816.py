# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2816 — ESPRESSObin V7 : demarrage depuis une cle USB en UNE ligne U-Boot, sans dependre du nom du disque.

Le boot.cmd de l'image demarre depuis `mmc` : depuis une cle USB il ne sert a rien. boot-usb.scr (U-Boot) doit etre sur la partition de demarrage de la cle."""
import struct
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
BOARD = RACINE / "board" / "espressobin-v7"
CMD = (BOARD / "boot-usb.cmd").read_text()
SCR = (BOARD / "boot-usb.scr").read_bytes()
BUILD = (RACINE / "image" / "build-image.sh").read_text()


def test_le_script_designe_la_racine_par_son_etiquette_pas_par_sda():
    """Le nom du disque change selon le port et les autres peripheriques ; l'etiquette « rootfs » est celle de l'image."""
    assert "root=LABEL=rootfs" in CMD and "root=/dev/sda2" not in CMD


def test_le_script_donne_la_commande_unique_a_taper():
    assert "usb start; load usb 0:1 ${loadaddr} boot-usb.scr; source ${loadaddr}" in CMD


def test_le_binaire_compile_est_un_script_uboot_et_correspond_au_source():
    """Un .scr perime (source modifie, binaire oublie) ferait demarrer l'ancienne version sans rien dire."""
    magic, = struct.unpack(">I", SCR[:4])
    assert magic == 0x27051956, "pas un en-tete U-Boot (uImage)"
    assert SCR[30] == 6, "type d'image : script (IH_TYPE_SCRIPT = 6)"
    charge = SCR[64:]
    assert b"root=LABEL=rootfs" in charge
    assert CMD.strip().splitlines()[-1].strip().encode() in charge       # derniere ligne : le source et le binaire sont synchrones


def test_la_construction_installe_boot_usb_dans_la_partition_de_demarrage():
    assert "boot-usb.scr" in BUILD and "${MNT}/boot/boot-usb.scr" in BUILD
