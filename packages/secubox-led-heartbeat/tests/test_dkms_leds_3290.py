# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-led-heartbeat (ref #3290) : pilote leds-is31fl319x livré par DKMS, MOCHAbin seulement.
gk2 (bus I2C neutralisé) reste inerte ; un échec de build ne fait jamais échouer dpkg."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SCRIPT = PKG / "usr" / "sbin" / "secubox-led-dkms"
DKMS_CONF = (PKG / "kmod" / "dkms.conf").read_text()
MAKEFILE = (PKG / "kmod" / "Makefile").read_text()
SOURCE_C = (PKG / "kmod" / "leds-is31fl319x.c").read_text()
RULES = (PKG / "debian" / "rules").read_text()
CONTROL = (PKG / "debian" / "control").read_text()
CHANGELOG = (PKG / "debian" / "changelog").read_text()


def conf(cle):
    m = re.search(rf'^{re.escape(cle)}="([^"]*)"', DKMS_CONF, re.M)
    assert m, cle
    return m.group(1)


# ---------- cohérence statique ----------

def test_dkms_conf_coherent_avec_makefile():
    assert conf("PACKAGE_NAME") == "secubox-leds"
    assert conf("BUILT_MODULE_NAME[0]") == "leds-is31fl319x"
    assert re.search(r"^obj-m\s*:=\s*leds-is31fl319x\.o$", MAKEFILE, re.M)
    assert conf("DEST_MODULE_LOCATION[0]").startswith("/updates")
    assert conf("AUTOINSTALL") == "yes"
    assert "${kernelver}" in conf("MAKE[0]") and "${kernel_source_dir}" in conf("MAKE[0]")
    # le Makefile ne force plus l'architecture croisée : DKMS construit nativement
    assert not re.search(r"^ARCH\s*\?=", MAKEFILE, re.M)
    assert "uname -r" in MAKEFILE and "KDIR ?=" in MAKEFILE


def test_version_dkms_vient_du_changelog():
    assert conf("PACKAGE_VERSION") == "@VERSION@"
    assert "dpkg-parsechangelog -SVersion" in RULES
    assert "s/@VERSION@/$(DKMS_VERSION)/" in RULES
    assert "usr/src/secubox-leds-$(DKMS_VERSION)" in RULES
    for f in ("leds-is31fl319x.c", "Makefile"):
        assert f"kmod/{f} $(DKMS_SRC)/{f}" in RULES
    premiere = CHANGELOG.splitlines()[0]
    assert premiere.startswith("secubox-led-heartbeat (2.2.0-1~trixie1) trixie;")
    # la version amont calculée comme debian/rules le fait
    ver = re.match(r"\S+ \(([^)]+)\)", premiere).group(1)
    assert re.sub(r"-[^-]*$", "", ver) == "2.2.0"


def test_dkms_et_entetes_en_recommends_pas_en_depends():
    depends = re.search(r"^Depends:(.*?)^\S", CONTROL, re.M | re.S).group(1)
    recommends = re.search(r"^Recommends:(.*?)^\S", CONTROL, re.M | re.S).group(1)
    assert "dkms" not in depends and "linux-headers" not in depends
    assert "dkms" in recommends and "linux-headers-arm64" in recommends


def test_source_c_reste_gpl_et_porte_les_ajouts():
    assert SOURCE_C.startswith("// SPDX-License-Identifier: GPL-2.0-only")
    assert "CMSD" not in SOURCE_C
    assert "Nikolaus Schaller" in SOURCE_C
    assert "v6.12.107" in SOURCE_C
    assert re.search(r"module_param\(write_delay_us, uint", SOURCE_C)
    assert "write_delay_us = 1000;" in SOURCE_C
    assert "usleep_range" in SOURCE_C
    # toutes les écritures du pilote passent par l'écriture temporisée
    assert "regmap_write(is31->regmap" not in SOURCE_C
    assert "KERNEL_VERSION(6, 10, 0)" in SOURCE_C and "devm_mutex_init(dev, &is31->lock)" in SOURCE_C


def test_postinst_et_prerm_appellent_le_script_sans_echouer():
    post = (PKG / "debian" / "postinst").read_text()
    pre = (PKG / "debian" / "prerm").read_text()
    assert '/usr/sbin/secubox-led-dkms install "$DKMS_VER" || true' in post
    assert '/usr/sbin/secubox-led-dkms remove "$DKMS_VER" || true' in pre
    # l'appel DKMS est après la garde board
    assert post.index("secubox-led-board") < post.index("secubox-led-dkms install")


@pytest.mark.parametrize("f", ["debian/postinst", "debian/prerm", "usr/sbin/secubox-led-dkms"])
def test_syntaxe_shell(f):
    sh = "sh" if f.startswith("debian/") and (PKG / f).read_text().startswith("#!/bin/sh") else "bash"
    r = subprocess.run([sh, "-n", str(PKG / f)], capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, r.stderr


def test_shellcheck_script():
    if not shutil.which("shellcheck"):
        pytest.skip("shellcheck absent")
    r = subprocess.run(["shellcheck", "-S", "warning", str(SCRIPT)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout


# ---------- simulation par racine de test ----------

def outil(d: Path, nom: str, corps: str) -> str:
    p = d / nom
    p.write_text("#!/bin/sh\n" + corps + "\n")
    p.chmod(0o755)
    return str(p)


@pytest.fixture
def racine(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    journal = tmp_path / "journal"
    journal.write_text("")
    (tmp_path / "modprobe.d").mkdir()
    (tmp_path / "i2c-1").mkdir()
    (tmp_path / "modules" / "6.12.107+deb13-arm64" / "build").mkdir(parents=True)
    env = {
        "PATH": f"{bin_}:/usr/bin:/bin",
        "SECUBOX_LED_BOARD": outil(bin_, "board", "exit 0"),
        "SECUBOX_DKMS": outil(bin_, "dkms", f'echo "dkms $*" >> {journal}; exit 0'),
        "SECUBOX_MODPROBE": outil(bin_, "modprobe", f'echo "modprobe $*" >> {journal}; exit 0'),
        "SECUBOX_MODINFO": outil(bin_, "modinfo", "exit 1"),
        "SECUBOX_MOKUTIL": str(bin_ / "mokutil-absent"),
        "SECUBOX_MODPROBE_D": str(tmp_path / "modprobe.d"),
        "SECUBOX_I2C_SYS": str(tmp_path / "i2c-1"),
        "SECUBOX_MODULES_DIR": str(tmp_path / "modules"),
        "SECUBOX_KVER": "6.12.107+deb13-arm64",
    }
    return tmp_path, bin_, journal, env


def lance(env, *args):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=20)


def test_mochabin_construit_installe_et_charge(racine):
    _, _, journal, env = racine
    r = lance(env, "install", "2.2.0")
    assert r.returncode == 0, r.stderr
    j = journal.read_text().splitlines()
    assert "dkms add -m secubox-leds -v 2.2.0" in j
    assert "dkms build -m secubox-leds -v 2.2.0 -k 6.12.107+deb13-arm64" in j
    assert "dkms install -m secubox-leds -v 2.2.0 -k 6.12.107+deb13-arm64 --force" in j
    assert j[-1] == "modprobe leds-is31fl319x"


def test_hors_mochabin_rien(racine):
    _, bin_, journal, env = racine
    env["SECUBOX_LED_BOARD"] = outil(bin_, "board-non", "exit 1")
    r = lance(env, "install", "2.2.0")
    assert r.returncode == 0
    assert journal.read_text() == ""
    assert "pas un MOCHAbin" in r.stdout


def test_gk2_bus_i2c_neutralise_rien(racine):
    tmp, _, journal, env = racine
    (tmp / "modprobe.d" / "blacklist-i2c.conf").write_text("blacklist i2c_mv64xxx\n")
    r = lance(env, "install", "2.2.0")
    assert r.returncode == 0
    assert journal.read_text() == ""
    assert "inerte" in r.stdout


def test_bus_i2c_absent_rien(racine):
    tmp, _, journal, env = racine
    (tmp / "i2c-1").rmdir()
    r = lance(env, "install", "2.2.0")
    assert r.returncode == 0 and journal.read_text() == ""


def test_echec_build_sort_zero_sans_charger(racine):
    _, bin_, journal, env = racine
    env["SECUBOX_DKMS"] = outil(bin_, "dkms-ko", f'echo "dkms $*" >> {journal}; [ "$1" = build ] && exit 10; exit 0')
    r = lance(env, "install", "2.2.0")
    assert r.returncode == 0
    assert "echec du build DKMS" in r.stdout
    assert "modprobe" not in journal.read_text()


def test_sans_dkms_ou_sans_entetes_message_et_zero(racine):
    tmp, _, journal, env = racine
    env["SECUBOX_DKMS"] = str(tmp / "dkms-absent")
    r = lance(env, "install", "2.2.0")
    assert r.returncode == 0 and "Recommends" in r.stdout
    env2 = dict(racine[3])
    (tmp / "modules" / "6.12.107+deb13-arm64" / "build").rmdir()
    r = lance(env2, "install", "2.2.0")
    assert r.returncode == 0 and "linux-headers-arm64" in r.stdout
    assert journal.read_text() == ""


def test_noyau_fournissant_le_pilote_pas_de_dkms(racine):
    _, bin_, journal, env = racine
    env["SECUBOX_MODINFO"] = outil(
        bin_, "modinfo-in", "echo /lib/modules/6.12/kernel/drivers/leds/leds-is31fl319x.ko")
    r = lance(env, "install", "2.2.0")
    assert r.returncode == 0
    assert journal.read_text().splitlines() == ["modprobe leds-is31fl319x"]


def test_secure_boot_message_sans_contournement(racine):
    _, bin_, _, env = racine
    env["SECUBOX_MOKUTIL"] = outil(bin_, "mokutil", "echo 'SecureBoot enabled'")
    r = lance(env, "install", "2.2.0")
    assert r.returncode == 0 and "MOK" in r.stdout


def test_remove_seulement_si_ajoute(racine):
    _, bin_, journal, env = racine
    r = lance(env, "remove", "2.2.0")
    assert r.returncode == 0
    assert "remove" not in journal.read_text()
    env["SECUBOX_DKMS"] = outil(
        bin_, "dkms-st", f'echo "dkms $*" >> {journal}; [ "$1" = status ] && echo "secubox-leds/2.2.0: added"; exit 0')
    lance(env, "remove", "2.2.0")
    assert "dkms remove -m secubox-leds -v 2.2.0 --all" in journal.read_text()


@pytest.mark.parametrize("args", [[], ["install"], ["install", "2.2.0;rm"], ["purge", "2.2.0"]])
def test_arguments_refuses(racine, args):
    _, _, journal, env = racine
    r = lance(env, *args)
    assert r.returncode == 2 and journal.read_text() == ""
