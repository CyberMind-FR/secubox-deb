# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3233 — le live réseau devient multi-carte : ce qui est propre à une carte (DTB, pilote Ethernet, console, adresses
de chargement, options du noyau) vit dans board/<carte>/live.env, comme le reste de la doctrine « tout par board »."""
import shlex
import subprocess
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
BUILD = ICI / "scripts" / "build-live-netboot.sh"
PSCI = (0x04000000, 0x04200000)        # réservé au firmware, Armada 7040 comme 3720


def charge(carte):
    env = {}
    for ligne in (ICI / "board" / carte / "live.env").read_text().splitlines():
        if ligne.strip() and not ligne.lstrip().startswith("#"):
            k, v = ligne.split("=", 1)
            env[k] = shlex.split(v)[0] if v else ""
    return env


def test_chaque_carte_declare_son_live():
    for carte in ("mochabin", "espressobin-v7"):
        e = charge(carte)
        for k in ("LIVE_NOM", "LIVE_DTB", "LIVE_PILOTE", "LIVE_CONSOLE", "LIVE_ETHACT", "LIVE_SCRIPT_ADDR",
                  "LIVE_KERNEL_ADDR", "LIVE_FDT_ADDR", "LIVE_RAMDISK_ADDR", "LIVE_BOOTARGS"):
            assert k in e, (carte, k)


def test_la_mochabin_garde_ses_reglages():
    e = charge("mochabin")
    assert (e["LIVE_NOM"], e["LIVE_DTB"], e["LIVE_PILOTE"]) == ("mochabin-live", "armada-7040-mochabin.dtb", "mvpp2")
    assert (e["LIVE_CONSOLE"], e["LIVE_ETHACT"]) == ("ttyS0,115200", "mvpp2-2")


def test_l_espressobin_a_son_dtb_eMMC_son_pilote_et_sa_console():
    e = charge("espressobin-v7")
    assert e["LIVE_NOM"] == "espressobin-live"
    assert e["LIVE_DTB"] == "armada-3720-espressobin-v7-emmc.dtb"
    assert (e["LIVE_PILOTE"], e["LIVE_CONSOLE"], e["LIVE_ETHACT"]) == ("mvneta", "ttyMV0,115200", "neta@30000")
    # le switch 88E6341 reste dans l'état laissé par U-Boot : mv88e6xxx ferait d'eth0 un simple conduit DSA
    assert "modprobe.blacklist=mv88e6xxx" in e["LIVE_BOOTARGS"]


def test_les_adresses_de_l_espressobin_tiennent_dans_1_go_hors_zone_reservee():
    e = charge("espressobin-v7")
    script, fdt, noyau, initrd = (int(e[k], 16) for k in
                                  ("LIVE_SCRIPT_ADDR", "LIVE_FDT_ADDR", "LIVE_KERNEL_ADDR", "LIVE_RAMDISK_ADDR"))
    for a in (script, fdt, noyau, initrd):
        assert not PSCI[0] <= a < PSCI[1]
    assert noyau >= PSCI[1] and noyau % 0x200000 == 0
    assert script + 0x100000 <= fdt and fdt + 0x100000 <= noyau     # script et DTB sous le noyau, sans chevauchement
    assert initrd >= noyau + 0x04000000                              # 64 Mo laissés au noyau (Debian ~37 Mo)
    assert initrd + 0x08000000 < 0x3F000000                          # 128 Mo d'initrd sous U-Boot relogé, 1 Go de RAM


def test_le_script_lit_la_carte_et_refuse_un_nom_douteux():
    s = BUILD.read_text()
    assert "--carte)" in s and '"$HERE/board/$carte/live.env"' in s
    assert 'case "$carte" in *[!a-z0-9-]*|"") die' in s
    assert '-name "$LIVE_DTB"' in s and '"$LIVE_PILOTE"' in s
    assert "armada-7040-mochabin.dtb" not in s and "mvpp2-2" not in s     # plus rien de la MOCHAbin en dur


def test_le_serveur_tftp_peut_differer_du_serveur_http():
    # ESPRESSObin sur le LAN de gk2 : TFTP sur 192.168.42.1 (même sous-réseau, pas de passerelle à U-Boot),
    # squashfs et images en HTTP sur 192.168.1.200:8099
    s = BUILD.read_text()
    assert "--tftp)" in s and "setenv serverip $tftp_ip" in s


def test_les_images_xz_de_la_release_sont_publiees_avec_leur_taille_decompressee():
    s = BUILD.read_text()
    assert "*.img.gz|*.img.xz)" in s
    assert "xz --robot -l" in s
    assert '>> "$w/out/http/images.txt"' in s


def test_options_inconnues_et_carte_absente_refusees(tmp_path):
    r = subprocess.run(["bash", str(BUILD), "--carte", "inexistante"], capture_output=True, text=True)
    assert r.returncode != 0


def test_la_page_netboot_liste_les_images_xz_a_quatre_colonnes(tmp_path):
    import importlib
    import sys
    from fastapi.testclient import TestClient
    sys.path.insert(0, str(ICI))
    sys.path.insert(0, str(ICI.parents[1] / "common"))
    tftp, http = tmp_path / "tftp", tmp_path / "http"
    (tftp / "espressobin-live").mkdir(parents=True)
    (tftp / "espressobin-live" / "boot.cmd").write_text(
        "#   setenv ethact neta@30000; setenv ipaddr <ip libre>; setenv serverip 192.168.42.1\n"
        "setenv serverip 192.168.42.1\n"
        "setenv bootargs console=ttyMV0,115200 boot=live components"
        " fetch=http://192.168.1.200:8099/espressobin-live/filesystem.squashfs ip=dhcp\n")
    (http / "espressobin-live").mkdir(parents=True)
    (http / "espressobin-live" / "images.txt").write_text(
        "secubox-minimal-espressobin-v7-trixie.img.xz 793388832 " + "a" * 64 + " 7516192768\n"
        "ancienne.img.gz 10 " + "b" * 64 + "\n"
        "trop.img.xz 10 " + "c" * 64 + " 1 2\n")
    (http / "espressobin-live" / "secubox-minimal-espressobin-v7-trixie.img.xz.sig").write_bytes(b"s")
    sys.modules.pop("api.lot", None)
    sys.modules.pop("api.main", None)
    main = importlib.import_module("api.main")
    main.TFTP_ROOT, main.HTTP_ROOT = tftp, http
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    live = TestClient(main.app).get("/live").json()["lives"][0]
    assert live["serveur"] == "192.168.42.1"
    assert live["images"] == [
        {"nom": "secubox-minimal-espressobin-v7-trixie.img.xz", "taille": 793388832, "sha256": "a" * 64,
         "signee": True, "taille_brute": 7516192768},
        {"nom": "ancienne.img.gz", "taille": 10, "sha256": "b" * 64, "signee": False, "taille_brute": None},
    ]
