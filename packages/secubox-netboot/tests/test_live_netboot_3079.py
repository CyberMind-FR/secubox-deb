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


def test_noyau_du_rootfs_quand_la_partition_de_boot_est_vide():
    # alpha.18 : partition de boot de la clé VIDE ; le noyau Debian est boot/vmlinuz-<version> dans le rootfs
    s = BUILD.read_text()
    assert "sed -n 's/^vmlinuz-//p'" in s and '"$w/root/boot/initrd.img-$v"' in s
    assert "gzip -t" in s and "ARM64" in s                 # booti veut une Image non compressée


def test_la_cle_live_usb_copie_le_noyau_versionne_et_son_propre_extlinux():
    s = (ICI.parents[1] / "image" / "build-mochabin-live-usb.sh").read_text()
    assert 'cp "${KERNEL_SRC}/vmlinuz" ' not in s               # le chemin qui laissait la partition vide
    assert 'vmlinuz-${KVER}' in s and 'initrd.img-${KVER}' in s
    bloc = s.split("<< EXTLINUX", 1)[1].split("\nEXTLINUX\n", 1)[0]
    assert "KERNEL /Image" in bloc and "INITRD /initrd.img" in bloc and "Image-mpcie-fix" not in bloc


def test_le_squashfs_ne_reste_pas_sous_srv():
    # gk2 : /srv est sur l'eMMC racine ; 2,2 Go de squashfs l'avaient fait passer de 74 à 89 %
    s = BUILD.read_text()
    assert 'mv -f "$h/filesystem.squashfs" "$stockage/filesystem.squashfs"' in s
    assert 'ln -sfn "$stockage/filesystem.squashfs" "$h/filesystem.squashfs"' in s
