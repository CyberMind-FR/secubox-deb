# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-rpi-dsi (#3399) : patches noyau, refus de version, ROOTPART, overlay, empaquetage."""
import os
import re
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HELPER = PKG / "usr" / "sbin" / "secubox-rpi-dsi"
BUILD = PKG / "dkms" / "secubox-rpi-dsi-build"
PATCHES = PKG / "patches"
DTS = PKG / "overlay" / "secubox-dsi-7inch.dts"
KTAG = "v6.12.107"
KFILES = [
    "drivers/gpu/drm/vc4/vc4_dsi.c",
    "drivers/gpu/drm/vc4/vc4_trace.h",
    "drivers/gpu/drm/vc4/Makefile",
    "drivers/gpu/drm/bridge/tc358762.c",
    "drivers/gpu/drm/panel/panel-simple.c",
    "drivers/input/touchscreen/edt-ft5x06.c",
]
URL = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/{}?h=" + KTAG

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="variables de test refusées sous root")


def run(args, env=None, check=False):
    e = dict(os.environ, SECUBOX_TEST="1")
    e.update(env or {})
    return subprocess.run([str(a) for a in args], env=e, capture_output=True, text=True,
                          timeout=120, check=check)


# --- sources v6.12.107 (réseau ; sinon skip) ------------------------------------------

@pytest.fixture(scope="module")
def ksrc(tmp_path_factory):
    racine = tmp_path_factory.mktemp("linux") / "linux-source-6.12"
    try:
        for f in KFILES:
            dest = racine / f
            dest.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(URL.format(f), headers={"User-Agent": "curl/8.5.0"})
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (URL fixe https)
                dest.write_bytes(r.read())
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        pytest.skip(f"sources {KTAG} indisponibles : {exc}")
    return racine


@pytest.fixture(scope="module")
def tarball(ksrc, tmp_path_factory):
    out = tmp_path_factory.mktemp("tar") / "linux-source-6.12.tar.xz"
    with tarfile.open(out, "w:xz") as t:
        t.add(ksrc, arcname="linux-source-6.12")
    return out


def test_patches_appliquent_sans_fuzz(ksrc, tmp_path):
    work = tmp_path / "w"
    shutil.copytree(ksrc, work)
    for p in sorted(PATCHES.glob("*.patch")):
        r = subprocess.run(["patch", "-d", str(work), "-p1", "--fuzz=0", "--forward", "--batch"],
                           stdin=p.open(), capture_output=True, text=True, timeout=60, check=False)
        assert r.returncode == 0, f"{p.name}: {r.stdout}{r.stderr}"
    assert "raspberrypi,7inch-dsi" in (work / KFILES[4]).read_text()
    assert "#define TRACE_INCLUDE_PATH ." in (work / KFILES[1]).read_text()
    assert "CFLAGS_vc4_trace_points.o := -I$(src)" in (work / KFILES[2]).read_text()


def test_prepare_extrait_et_patche(tarball, tmp_path):
    dest = tmp_path / "src"
    r = run([BUILD, "prepare", "6.12.107+deb13-arm64", dest],
            env={"SECUBOX_RPI_DSI_TARBALL": str(tarball), "SECUBOX_RPI_DSI_SRCVER": "6.12.107-1",
                 "SECUBOX_RPI_DSI_PATCHES": str(PATCHES)})
    assert r.returncode == 0, r.stderr
    assert "raspberrypi,7inch-dsi" in (dest / KFILES[4]).read_text()
    assert (dest / "drivers/gpu/drm/vc4/vc4_drv.c").exists() is False  # seuls les fichiers fournis


def test_version_differente_refusee(tarball, tmp_path):
    dest = tmp_path / "src"
    r = run([BUILD, "prepare", "6.12.110+deb13-arm64", dest],
            env={"SECUBOX_RPI_DSI_TARBALL": str(tarball), "SECUBOX_RPI_DSI_SRCVER": "6.12.107-1",
                 "SECUBOX_RPI_DSI_PATCHES": str(PATCHES)})
    assert r.returncode == 1
    assert "ne correspond pas" in r.stderr
    assert not dest.exists()


def test_patch_refuse_aucune_source_laissee(tarball, tmp_path):
    mauvais = tmp_path / "p"
    mauvais.mkdir()
    shutil.copy(PATCHES / "0004-panel-simple-raspberrypi-7inch.patch", mauvais / "0001.patch")
    shutil.copy(PATCHES / "0004-panel-simple-raspberrypi-7inch.patch", mauvais / "0002.patch")  # 2e passe refusée
    dest = tmp_path / "src"
    r = run([BUILD, "prepare", "6.12.107+deb13-arm64", dest],
            env={"SECUBOX_RPI_DSI_TARBALL": str(tarball), "SECUBOX_RPI_DSI_SRCVER": "6.12.107-1",
                 "SECUBOX_RPI_DSI_PATCHES": str(mauvais)})
    assert r.returncode == 1
    assert "refusé" in r.stderr
    assert not dest.exists()


def test_source_absente_refusee(tmp_path):
    r = run([BUILD, "prepare", "6.12.107+deb13-arm64", tmp_path / "s"],
            env={"SECUBOX_RPI_DSI_TARBALL": str(tmp_path / "absent.tar.xz"), "SECUBOX_RPI_DSI_SRCVER": "6.12.107-1"})
    assert r.returncode == 1 and "absent" in r.stderr


# --- ROOTPART / overlay / cible -------------------------------------------------------

@pytest.fixture
def box(tmp_path):
    (tmp_path / "overlays").mkdir()
    (tmp_path / "log").mkdir()
    dtbo = tmp_path / "x.dtbo"
    dtbo.write_bytes(b"\xd0\x0d\xfe\xed")
    model = tmp_path / "model"
    model.write_bytes(b"Raspberry Pi 4 Model B Rev 1.5\0")
    env = {
        "SECUBOX_RPI_DSI_MODEL": str(model),
        "SECUBOX_RPI_DSI_RFCONF": str(tmp_path / "raspi-firmware"),
        "SECUBOX_RPI_DSI_RFCUSTOM": str(tmp_path / "raspi-firmware-custom"),
        "SECUBOX_RPI_DSI_OVERLAYS": str(tmp_path / "overlays"),
        "SECUBOX_RPI_DSI_DTBO": str(dtbo),
        "SECUBOX_RPI_DSI_AUDIT": str(tmp_path / "log" / "audit.log"),
        "SECUBOX_RPI_DSI_ROOTUUID": "0b9c6d1e-1111-2222-3333-444455556666",
        "SECUBOX_RPI_DSI_INITRAMFS": "true",
    }
    return tmp_path, env


@pytest.mark.parametrize("modele,attendu", [
    (b"Raspberry Pi 4 Model B Rev 1.5\0", 0),
    (b"Raspberry Pi 400 Rev 1.0\0", 0),
    (b"Raspberry Pi 3 Model B Plus Rev 1.3\0", 1),
    (b"Globalscale MOCHAbin\0", 1),
])
def test_is_target(box, modele, attendu):
    d, env = box
    (d / "model").write_bytes(modele)
    assert run([HELPER, "is-target"], env).returncode == attendu


def test_rootpart_ajoute_si_absent(box):
    d, env = box
    (d / "raspi-firmware").write_text("CONSOLES=auto\n#ROOTPART=/dev/mmcblk0p2\n")
    assert run([HELPER, "rootpart-ok"], env).returncode == 1
    assert run([HELPER, "update-initramfs"], env).returncode == 1  # refusé tant que vide
    assert run([HELPER, "ensure-rootpart"], env).returncode == 0
    txt = (d / "raspi-firmware").read_text()
    assert "ROOTPART=UUID=0b9c6d1e-1111-2222-3333-444455556666" in txt
    assert "#ROOTPART=/dev/mmcblk0p2" in txt and "CONSOLES=auto" in txt
    assert run([HELPER, "rootpart-ok"], env).returncode == 0
    assert run([HELPER, "update-initramfs"], env).returncode == 0
    assert "ROOTPART=UUID=" in (d / "log" / "audit.log").read_text()


def test_rootpart_existant_jamais_ecrase(box):
    d, env = box
    (d / "raspi-firmware").write_text('ROOTPART="/dev/sda2"\n')
    assert run([HELPER, "ensure-rootpart"], env).returncode == 0
    assert (d / "raspi-firmware").read_text() == 'ROOTPART="/dev/sda2"\n'


def test_rootpart_vide_remplace(box):
    d, env = box
    (d / "raspi-firmware").write_text("ROOTPART=\n")
    assert run([HELPER, "ensure-rootpart"], env).returncode == 0
    lignes = [x for x in (d / "raspi-firmware").read_text().splitlines() if x.startswith("ROOTPART=")]
    assert lignes == ["ROOTPART=UUID=0b9c6d1e-1111-2222-3333-444455556666"]


def test_rootpart_uuid_introuvable(box):
    d, env = box
    env["SECUBOX_RPI_DSI_ROOTUUID"] = "pas un uuid; rm"
    r = run([HELPER, "ensure-rootpart"], env)
    assert r.returncode == 1
    assert not (d / "raspi-firmware").exists()


def test_overlay_idempotent_puis_retire(box):
    d, env = box
    (d / "raspi-firmware-custom").write_text("dtparam=audio=on\n")
    for _ in range(2):
        assert run([HELPER, "install-overlay"], env).returncode == 0
    txt = (d / "raspi-firmware-custom").read_text()
    assert txt.count("dtoverlay=secubox-dsi-7inch") == 1 and "dtparam=audio=on" in txt
    assert (d / "overlays" / "secubox-dsi-7inch.dtbo").exists()
    assert run([HELPER, "remove-overlay"], env).returncode == 0
    assert (d / "raspi-firmware-custom").read_text() == "dtparam=audio=on\n"
    assert not (d / "overlays" / "secubox-dsi-7inch.dtbo").exists()


# --- overlay / empaquetage -------------------------------------------------------------

@pytest.mark.skipif(shutil.which("dtc") is None, reason="dtc absent")
def test_dts_compile(tmp_path):
    out = tmp_path / "o.dtbo"
    subprocess.run(["dtc", "-@", "-q", "-I", "dts", "-O", "dtb", "-o", str(out), str(DTS)],
                   check=True, timeout=60, capture_output=True, text=True)
    assert out.stat().st_size > 0


def test_tactile_fragment_separe_desactivable():
    t = DTS.read_text()
    frag4 = t[t.index("fragment@4 {"):t.index("__overrides__")]
    assert "edt,edt-ft5506" in frag4 and "touchscreen-inverted-x" in frag4
    assert "ts@38" not in t.split("fragment@4 {")[0]
    assert "vcc-supply" not in frag4 and "reset-gpios" not in frag4
    assert re.search(r'touch\s*=\s*<0>,"\+4";', t)


def test_dkms_conf_quatre_modules_autoinstall():
    c = (PKG / "dkms" / "dkms.conf").read_text()
    assert sorted(re.findall(r'BUILT_MODULE_NAME\[\d\]="([^"]+)"', c)) == \
        ["edt-ft5x06", "panel-simple", "tc358762", "vc4"]
    assert len(re.findall(r'DEST_MODULE_LOCATION\[\d\]="/updates/dkms"', c)) == 4
    assert 'AUTOINSTALL="yes"' in c


def test_debian_conforme():
    deb = PKG / "debian"
    assert (deb / "compat").read_text().strip() == "13"
    ctl = (deb / "control").read_text()
    assert "Standards-Version: 4.6.2" in ctl and "Architecture: arm64" in ctl
    assert (deb / "changelog").read_text().startswith("secubox-rpi-dsi (0.1.0-1~trixie1) trixie;")
    assert "GPL-2.0" in (deb / "copyright").read_text()
    for s in ("postinst", "prerm", "postrm"):
        subprocess.run(["sh", "-n", str(deb / s)], check=True, timeout=30)
    assert "/boot/firmware/config.txt" not in (deb / "postinst").read_text()


def test_postinst_hors_cible_inerte():
    p = (PKG / "debian" / "postinst").read_text()
    i_cible = p.index("is-target")
    assert p.index("ensure-rootpart") > i_cible and p.index("dkms add") > i_cible
    assert p.index("\"$H\" ensure-rootpart") < p.index("\"$H\" update-initramfs")
