# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3233 — live LÉGER (1 Go de RAM) : Debian minimale + réseau + SSH + outils de flash, démarrage normal (jamais rescue).
Un seul fichier sert de clé USB et d'entrée à build-live-netboot.sh (p1 FAT : Image, initrd, DTB ; p2 ext4 : racine)."""
import os
import subprocess
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
LEGER = ICI / "scripts" / "build-live-leger.sh"
NETFLASH = ICI / "installer" / "sbx-netflash"


def texte():
    return LEGER.read_text()


def test_script_executable_et_valide():
    assert os.access(LEGER, os.X_OK)
    subprocess.run(["bash", "-n", str(LEGER)], check=True)


def test_debian_minimale_avec_le_necessaire_du_flash():
    s = texte()
    assert "--variant=minbase" in s and "--arch=arm64" in s
    for paquet in ("linux-image-arm64", "live-boot", "openssh-server", "curl", "openssl", "xz-utils", "python3-argon2"):
        assert paquet in s, paquet
    for lourd in ("nginx", "haproxy", "python3-fastapi", "secubox-"):          # pas de pile SecuBox : 1 Go de RAM
        assert f",{lourd}" not in s and f" {lourd}," not in s, lourd


def test_meme_format_que_la_cle_live_mochabin():
    # build-live-netboot.sh monte p1 (Image, initrd.img, DTB) et p2 (racine) : le live léger suit ce format
    s = texte()
    assert "mkfs.vfat" in s and "SBXBOOT" in s and "mkfs.ext4" in s and "SBXLIVE" in s
    assert '"$w/boot/Image"' in s and '"$w/boot/initrd.img"' in s


def test_la_carte_vient_de_son_live_env():
    s = texte()
    assert '"$HERE/board/$carte/live.env"' in s and 'case "$carte" in *[!a-z0-9-]*|"") die' in s
    assert "$LIVE_DTB" in s and "$LIVE_CONSOLE" in s and "$LIVE_BOOTARGS" in s and "$LIVE_KERNEL_ADDR" in s


def test_demarrage_usb_par_le_u_boot_usine():
    s = texte()
    assert "fatload usb 0:1" in s and "root=LABEL=SBXLIVE" in s and "rootwait" in s
    assert "sbx_srv=$srv" in s and "sbx_dir=$LIVE_NOM" in s       # sans fetch=, sbx-netflash sait où chercher
    assert "systemd.unit=rescue.target" not in s                 # arbitrage du 2026-10-24 : le live reste en mode normal


def test_acces_console_serie_et_ssh_par_cle_seulement():
    s = texte()
    assert "serial-getty@" in s and "--autologin root" in s     # la console série est physique : banc
    assert "passwd -l root" in s                                 # aucun mot de passe
    assert "PermitRootLogin prohibit-password" in s and "PasswordAuthentication no" in s
    assert "authorized_keys" in s


def test_seule_la_cle_publique_entre_dans_le_live():
    s = texte()
    assert "netboot-image.pub" in s
    assert ".key" not in s.replace("authorized_keys", "")


def test_les_montages_du_chroot_sont_toujours_defaits():
    s = texte()
    assert "trap nettoie EXIT" in s
    corps = s[s.index("nettoie() {"):s.index("trap nettoie EXIT")]
    assert 'for m in /dev/pts /dev /sys /proc; do umount -l "$w/root$m"' in corps     # du plus profond au moins profond


def test_sbx_netflash_lit_sbx_dir_depuis_le_noyau():
    s = NETFLASH.read_text()
    assert "s#^sbx_dir=##p" in s
