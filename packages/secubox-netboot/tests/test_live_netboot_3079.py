# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3079 — live MOCHAbin par TFTP et flash eMMC depuis le live."""
import os
import subprocess
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
BUILD = ICI / "scripts" / "build-live-netboot.sh"
FLASH = ICI / "installer" / "sbx-netflash"


def test_scripts_valides_en_bash():
    for f in (BUILD, FLASH):
        assert os.access(f, os.X_OK), f
        subprocess.run(["bash", "-n", str(f)], check=True)


def test_le_live_recupere_son_rootfs_en_http_et_garde_la_cle_privee_sur_le_serveur():
    s = BUILD.read_text()
    assert "boot=live" in s and "fetch=http://$srv/$nom/filesystem.squashfs" in s and "ip=dhcp" in s
    assert "booti" in s and "mkimage" in s
    # le fstab de la clé USB attend sa partition : il est remplacé, sinon le live tomberait en mode urgence
    assert '> "$w/rootfs/etc/fstab"' in s
    # seule la clé PUBLIQUE entre dans le rootfs
    assert '"$PUB" "$w/rootfs/etc/secubox/netboot-image.pub"' in s
    assert '"$KEY" "$w/rootfs' not in s


def test_le_flash_verifie_la_signature_avant_d_ecrire():
    s = FLASH.read_text()
    v = s.index("openssl dgst -sha256 -verify")
    e = s.index("exec secubox-flash-emmc")
    assert v < e
    assert "SIGNATURE INVALIDE" in s and 'rm -f "$dest" "$dest.sig"' in s
    assert "MemAvailable" in s                    # l'image transite par la RAM


def test_le_flash_refuse_un_nom_avec_chemin():
    s = FLASH.read_text()
    assert 'case "$image" in */*|*..*|"") fail' in s


def test_le_paquet_embarque_le_flasheur():
    assert "image/sbin/secubox-flash-emmc" in (ICI / "debian" / "rules").read_text()
