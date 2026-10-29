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
    # #3271 : la signature est vérifiée EN FLUX par secubox-flash-emmc ; un échec invalide l'eMMC
    s = FLASH.read_text()
    assert 'opts=(--stdin "$format" --sig "$TRAVAIL/$image.sig" --pub "$PUB" --sha256 "$sha" --auto)' in s
    f = (ICI.parents[1] / "image" / "sbin" / "secubox-flash-emmc").read_text()
    assert 'openssl dgst -sha256 -verify "$pub" -signature "$sig"' in f


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


def test_les_adresses_de_chargement_evitent_la_zone_reservee_du_firmware():
    # Armada 7040 : 0x04000000-0x04200000 réservé (PSCI/ATF). Le noyau Debian 6.12 (~37 Mo)
    # chargé à 0x02080000 débordait dessus : TFTP tronqué puis « Synchronous Abort » au booti.
    # #3233 : les adresses vivent dans board/mochabin/live.env ; le script les pose telles quelles.
    import re
    env = dict(re.findall(r"^(LIVE_\w+_ADDR)=(0x[0-9a-fA-F]+)$", (ICI / "board" / "mochabin" / "live.env").read_text(), re.M))
    noyau, fdt, initrd = (int(env[k], 16) for k in ("LIVE_KERNEL_ADDR", "LIVE_FDT_ADDR", "LIVE_RAMDISK_ADDR"))
    s = BUILD.read_text()
    for k, var in (("kernel_addr_r", "LIVE_KERNEL_ADDR"), ("fdt_addr_r", "LIVE_FDT_ADDR"), ("ramdisk_addr_r", "LIVE_RAMDISK_ADDR")):
        assert f"setenv {k} ${var}" in s
    assert noyau >= 0x04200000 and noyau % 0x200000 == 0
    assert fdt >= noyau + 0x04000000          # 64 Mo laissés au noyau décompressé
    assert initrd >= fdt + 0x00100000
    assert initrd + 0x08000000 < 0x7F000000   # 128 Mo d'initrd sous U-Boot relogé


def test_un_echec_tftp_arrete_le_script_au_lieu_de_lancer_booti():
    s = BUILD.read_text()
    for f in ("Image", "board.dtb", "initrd.img"):
        assert f"$nom/{f} || exit" in s


AJOUT = ICI / "scripts" / "live-initrd-modules.sh"


def test_l_initrd_recoit_squashfs_et_overlay(tmp_path):
    # DUT 2026-10-23 : « request_module fs-squashfs succeeded, but still no fs? » puis BOOT FAILED.
    # L'initrd de l'image eMMC ne connaît que l'ext4 ; live-boot doit monter un squashfs sous overlay.
    import shutil
    import pytest
    for outil in ("unmkinitramfs", "lsinitramfs", "depmod", "cpio", "zstd"):
        if not shutil.which(outil):
            pytest.skip(f"{outil} absent")
    v = os.uname().release
    vrai = list(Path(f"/lib/modules/{v}/kernel/fs/overlayfs").glob("overlay.ko*"))
    if not vrai:
        pytest.skip("pas de module noyau réel pour le test")
    ext = vrai[0].name[len("overlay"):]
    racine = tmp_path / "rootfs"
    for m in ("fs/squashfs/squashfs", "fs/overlayfs/overlay"):
        d = racine / "lib/modules" / v / "kernel" / Path(m).parent
        d.mkdir(parents=True)
        shutil.copy(vrai[0], d / (Path(m).name + ext))
    ird = tmp_path / "ird"
    (ird / "scripts/live-bottom").mkdir(parents=True)
    (ird / "init").write_text("#!/bin/sh\n")
    (ird / "lib/modules" / v).mkdir(parents=True)
    initrd = tmp_path / "initrd.img"
    subprocess.run(f"cd {ird} && find . | cpio -o -H newc --quiet | gzip > {initrd}", shell=True, check=True)

    r = subprocess.run(["bash", str(AJOUT), str(initrd), str(racine)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    lst = subprocess.run(["lsinitramfs", str(initrd)], capture_output=True, text=True, check=True).stdout
    assert "kernel/fs/squashfs/squashfs.ko" in lst and "kernel/fs/overlayfs/overlay.ko" in lst
    assert "scripts/live-bottom" in lst and "init" in lst.split()
    sortie = tmp_path / "x"
    subprocess.run(["unmkinitramfs", str(initrd), str(sortie)], check=True)
    dep = next(sortie.rglob(f"lib/modules/{v}/modules.dep")).read_text()
    assert "kernel/fs/squashfs/squashfs.ko" in dep


def test_la_construction_ajoute_les_modules_et_le_verifie():
    s = BUILD.read_text()
    assert '"$HERE/scripts/live-initrd-modules.sh"' in s
    assert "squashfs\\.ko" in s and "overlay\\.ko" in s


def test_l_initrd_du_live_leve_la_liste_noire_de_squashfs_et_garde_le_reste(tmp_path):
    # DUT 2026-10-23, 2e essai : squashfs bien présent mais secubox-hardening le met en liste noire
    # (/etc/modprobe.d/secubox-blacklist.conf, recopié dans l'initrd) : la demande du noyau
    # par alias « fs-squashfs » est refusée → « still no fs? ». Le live, lui, est un squashfs.
    import shutil
    import pytest
    for outil in ("unmkinitramfs", "depmod", "cpio", "zstd"):
        if not shutil.which(outil):
            pytest.skip(f"{outil} absent")
    v = os.uname().release
    vrai = list(Path(f"/lib/modules/{v}/kernel/fs/overlayfs").glob("overlay.ko*"))
    if not vrai:
        pytest.skip("pas de module noyau réel pour le test")
    ext = vrai[0].name[len("overlay"):]
    racine = tmp_path / "rootfs"
    for m in ("fs/squashfs/squashfs", "fs/overlayfs/overlay"):
        d = racine / "lib/modules" / v / "kernel" / Path(m).parent
        d.mkdir(parents=True)
        shutil.copy(vrai[0], d / (Path(m).name + ext))
    ird = tmp_path / "ird"
    (ird / "etc/modprobe.d").mkdir(parents=True)
    (ird / "lib/modules" / v).mkdir(parents=True)
    (ird / "init").write_text("#!/bin/sh\n")
    (ird / "etc/modprobe.d/secubox-blacklist.conf").write_text(
        "# durcissement\nblacklist cramfs\nblacklist squashfs\ninstall squashfs /bin/false\nblacklist udf\n")
    initrd = tmp_path / "initrd.img"
    subprocess.run(f"cd {ird} && find . | cpio -o -H newc --quiet | gzip > {initrd}", shell=True, check=True)

    r = subprocess.run(["bash", str(AJOUT), str(initrd), str(racine)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    sortie = tmp_path / "x"
    subprocess.run(["unmkinitramfs", str(initrd), str(sortie)], check=True)
    conf = next(sortie.rglob("etc/modprobe.d/secubox-blacklist.conf")).read_text()
    assert "blacklist squashfs" not in conf
    assert "install squashfs" not in conf
    assert "blacklist cramfs" in conf and "blacklist udf" in conf


def test_le_live_garde_le_reseau_de_l_initrd():
    # DUT 2026-10-23 : réseau OK dans l'initrd (squashfs téléchargé), perdu ensuite :
    #  - mv88e6xxx (module sur noyau Debian) chargé tard : mvpp2 rouvre ses ports, eth2 sans porteuse (#2004) ;
    #  - le netplan de l'image met eth1 (conduit DSA) et eth2 dans br-lan : plus d'adresse, lan0..3 sourds.
    # #3233 : les options propres à la carte viennent de board/mochabin/live.env (LIVE_BOOTARGS, 2e ligne bootargs).
    import re
    s = BUILD.read_text()
    lignes = [x for x in s.splitlines() if x.startswith("setenv bootargs")]
    assert any("$LIVE_BOOTARGS" in x for x in lignes)
    env = (ICI / "board" / "mochabin" / "live.env").read_text()
    extra = re.search(r'^LIVE_BOOTARGS="([^"]*)"$', env, re.M).group(1)
    assert all(len(x.replace("$LIVE_BOOTARGS", extra)) < 200 for x in lignes)  # tampon de ligne U-Boot parfois à 256
    assert "modprobe.blacklist=mv88e6xxx" in extra
    assert "systemd.mask=systemd-networkd.service" in extra
    assert "systemd.mask=systemd-networkd.socket" in extra


def test_sbx_netflash_montre_l_erreur_du_telechargement_de_la_liste():
    s = FLASH.read_text()
    ligne = next(l for l in s.splitlines() if "images.txt" in l and "telecharge" in l)
    assert "2>&1" not in ligne


def test_l_image_ne_passe_plus_par_un_tmpfs():
    # DUT 2026-10-24 : /run est un tmpfs à 10 % de la RAM ; #3271 : le tmpfs à la taille de l'image épuisait la
    # mémoire d'un live complet. L'image s'écrit en flux (test_netboot_mochabin_3271).
    s = FLASH.read_text()
    assert "mount -t tmpfs" not in s and 'dest="$TRAVAIL/image/$image"' not in s


def test_le_live_demarre_en_mode_normal():
    # Arbitrage du 2026-10-24 : rescue.target ne permet pas de lancer les outils ; le live reste
    # en mode normal, sbx-netflash libère la mémoire lui-même quand elle manque.
    s = BUILD.read_text()
    assert "systemd.unit=rescue.target" not in s


def test_sbx_netflash_libere_la_memoire_seulement_si_elle_manque():
    # DUT 2026-10-24 : pile SecuBox du live à 6,9 Go sur 8 ; arrêt manuel des services → 5,2 Go libres.
    # #3271 : en flux, quelques Mo suffisent ; la pile n'est arrêtée qu'au plus bas (256 Mo)
    s = FLASH.read_text()
    assert 'if [ "${dispo:-0}" -le $(( 256 * 1048576 )) ]; then libere_memoire; fi' in s
    assert "systemctl stop 'secubox-*'" in s
    assert "pkill -x" in s
