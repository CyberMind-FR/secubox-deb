# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3091 — le boot.cmd eMMC de la MOCHAbin fixe ses adresses hors de la zone réservée du firmware."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
BOOTCMD = RACINE / "board" / "mochabin" / "boot.cmd"


def test_adresses_explicites_au_dessus_de_la_zone_reservee():
    # Banc 2026-10-24, U-Boot usine 2020.10 : « Reading file would overwrite reserved memory »,
    # « ERROR: No kernel found! ». Ses kernel_addr_r par défaut mettent un noyau de ~37 Mo sur 0x04000000.
    s = BOOTCMD.read_text()
    adr = {k: int(v, 16) for k, v in re.findall(r"^setenv (\w+_addr_r) (0x[0-9a-fA-F]+)", s, re.M)}
    noyau, fdt, initrd = adr["kernel_addr_r"], adr["fdt_addr_r"], adr["ramdisk_addr_r"]
    assert noyau >= 0x04200000 and noyau % 0x200000 == 0
    assert fdt >= noyau + 0x04000000
    assert initrd >= fdt + 0x00100000
    assert initrd + 0x08000000 < 0x7F000000
    # fixées avant le premier chargement
    assert s.index("setenv kernel_addr_r") < s.index("load ${bootpart} ${kernel_addr_r}")
