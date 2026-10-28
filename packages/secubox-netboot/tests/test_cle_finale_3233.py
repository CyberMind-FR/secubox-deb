# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3233 — clé USB « finale » : l'image système elle-même tourne sur la clé (tests) et s'écrit seule sur l'eMMC
(autoflash, démarrage par autoflash.scr) pour l'intégration définitive. Étiquettes propres à la clé : la racine de
l'eMMC (LABEL=rootfs) n'est jamais confondue avec celle de la clé (LABEL=rootfs-usb)."""
import os
import subprocess
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
CLE = ICI / "scripts" / "build-cle-finale.sh"
AUTO = ICI / "installer" / "sbx-autoflash"
UNITE = ICI / "installer" / "sbx-autoflash.service"
BUILD = ICI / "scripts" / "build-live-netboot.sh"


def test_scripts_executables_et_valides():
    for f in (CLE, AUTO):
        assert os.access(f, os.X_OK), f
        subprocess.run(["bash", "-n", str(f)], check=True)


def test_la_signature_est_verifiee_avant_toute_construction():
    s = CLE.read_text()
    assert s.index('openssl dgst -sha256 -verify "$pub"') < s.index('sgdisk -e "$w/cle.img"')


def test_etiquettes_et_identifiants_propres_a_la_cle():
    s = CLE.read_text()
    assert "sgdisk -G" in s                                        # GUID du disque et des partitions renouvelés
    assert 'e2label "${loop}p2" rootfs-usb' in s and 'e2label "${loop}p3" data-usb' in s
    assert 'fatlabel "${loop}p1" BOOTUSB' in s
    assert "tune2fs -U random" in s
    for a, b in (("LABEL=rootfs ", "LABEL=rootfs-usb "), ("LABEL=data ", "LABEL=data-usb "), ("LABEL=boot ", "LABEL=BOOTUSB ")):
        assert f"s/^{a}/{b}/" in s, a                                # fstab de la clé


def test_scripts_u_boot_de_la_cle():
    s = CLE.read_text()
    assert "root=LABEL=rootfs-usb" in s and "boot-usb.cmd" in s
    assert "autoflash.cmd" in s and "sbx_autoflash=1" in s and "sdhci.debug_quirks2=0x40" in s
    assert "mkimage" in s


def test_partition_sbxflash_et_cle_privee_jamais_copiee():
    s = CLE.read_text()
    assert "SBXFLASH" in s and "mkfs.ext4" in s
    assert "netboot-image.pub" in s
    for ligne in s.splitlines():
        if '"$KEY"' in ligne:                                            # la clé privée ne sert qu'à signer, sur le serveur
            assert not any(x in ligne for x in ("install ", "cp ", "ln ", "mv ")), ligne


def test_publication_a_cote_du_live():
    s = CLE.read_text()
    assert "cle-usb.img.gz" in s and "cle-usb.txt" in s
    assert "tester\\t" in s and "autoflash\\t" in s
    b = BUILD.read_text()
    assert '"$cible.avant"/cle-usb.*' in b                          # republier le live ne perd pas la clé publiée


def test_l_unite_ne_part_qu_avec_sbx_autoflash():
    u = UNITE.read_text()
    assert "ConditionKernelCommandLine=sbx_autoflash=1" in u and "ExecStart=/usr/local/sbin/sbx-autoflash" in u
    assert "Type=oneshot" in u and "journal+console" in u


def _auto(expr, **env):
    return subprocess.run(["bash", "-c", f'SBX_AUTOFLASH_SOURCE=1 source "$0"; {expr}', str(AUTO)],
                          capture_output=True, text=True, env={**os.environ, **env})


def test_autoflash_seulement_sur_demande(tmp_path):
    oui, non = tmp_path / "oui", tmp_path / "non"
    oui.write_text("console=ttyMV0,115200 root=LABEL=rootfs-usb sbx_autoflash=1 rootwait\n")
    non.write_text("console=ttyMV0,115200 root=LABEL=rootfs-usb sbx_autoflash=10\n")
    assert _auto(f'demande_autoflash "{oui}"').returncode == 0
    assert _auto(f'demande_autoflash "{non}"').returncode != 0


@pytest.mark.parametrize("cas", ["une", "aucune", "deux", "sans_sig"])
def test_une_seule_image_signee(tmp_path, cas):
    if cas in ("une", "deux"):
        (tmp_path / "a.img.xz").write_bytes(b"a")
        (tmp_path / "a.img.xz.sig").write_bytes(b"s")
    if cas == "deux":
        (tmp_path / "b.img.gz").write_bytes(b"b")
        (tmp_path / "b.img.gz.sig").write_bytes(b"s")
    if cas == "sans_sig":
        (tmp_path / "a.img.xz").write_bytes(b"a")
    r = _auto(f'choisit_image "{tmp_path}"')
    if cas == "une":
        assert r.returncode == 0 and r.stdout.strip() == str(tmp_path / "a.img.xz")
    else:
        assert r.returncode != 0


def test_l_ecriture_passe_par_le_flux_verifie():
    # l'empreinte calculée AVANT la vérification de signature est imposée au flux : un fichier changé entre-temps
    # ne correspond plus, et l'eMMC est invalidée (secubox-flash-emmc --stdin)
    s = AUTO.read_text()
    s = s[s.index("main() {"):]
    i_sha, i_sig, i_flash = s.index("sha256sum"), s.index("verifie_signature \"$PUB\""), s.index("secubox-flash-emmc --stdin")
    assert i_sha < i_sig < i_flash
    assert '--sha256 "$sha"' in s and "--auto" in s and "--no-reboot" in s
    assert "systemctl poweroff" in s



def test_la_cle_finale_refuse_une_cle_privee_et_charge_la_carte():
    s = CLE.read_text()
    assert "grep -q 'PRIVATE KEY' \"$pub\"" in s and 'openssl pkey -pubin -in "$pub" -noout' in s
    assert 'charge_live_env "$carte" "$HERE" || die' in s
    assert "rm -rf --one-file-system" in s
