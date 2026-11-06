# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Installateur : le live charge squashfs malgré le durcissement, et n'efface pas un disque non vide sans accord (#3529)."""
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1] / "image/build-installer-iso.sh").read_text(encoding="utf-8")


def test_initramfs_regenere_avec_squashfs_avant_le_squashfs():
    modules = SCRIPT.index("squashfs loop overlay")
    regenere = SCRIPT.index('update-initramfs -u -k all', modules)
    assert regenere < SCRIPT.index('mksquashfs "${ROOTFS}"') < SCRIPT.index('cp "${ROOTFS}/boot/initrd.img-"')


def test_sans_console_un_disque_non_vide_est_refuse():
    bloc = SCRIPT[SCRIPT.index("Sans console"):SCRIPT.index("Headless mode: auto-installing")]
    assert "lsblk" in bloc and "secubox.effacer=1" in bloc and "err " in bloc
