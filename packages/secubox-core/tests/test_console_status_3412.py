# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Console d'une box à écran public (ref #3412) : secubox-status juste, console en UTF-8, pas d'autologin root dans les images."""
import re
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
STATUS = RACINE / "packages" / "secubox-core" / "usr" / "bin" / "secubox-status"
POSTINST = RACINE / "packages" / "secubox-core" / "debian" / "postinst"
IMAGES = [RACINE / "image" / n for n in ("build-rpi-usb.sh", "build-image.sh", "build-live-usb.sh")]


def _status(tmp_path, defauts: str, agreg_actif=True, sante=True, *args):
    b = tmp_path / "bin"
    b.mkdir()
    stubs = {
        "systemctl": "case \"$1\" in is-active) case \"$3\" in secubox-aggregator) exit %d;; *) exit 0;; esac;; list-unit-files) echo \"$2 enabled\";; esac" % (0 if agreg_actif else 3),
        "curl": "exit %d" % (0 if sante else 7),
        "hostname": "[ \"$1\" = -I ] && echo '192.168.1.42 10.0.0.1' || echo gk7",
    }
    for n, c in stubs.items():
        (b / n).write_text("#!/bin/sh\n" + c + "\n")
        (b / n).chmod(0o755)
    d = tmp_path / "secubox"
    d.write_text(defauts)
    r = subprocess.run(["bash", str(STATUS), *args], capture_output=True, text=True,
                       env={"PATH": f"{b}:/usr/bin:/bin", "SECUBOX_DEFAULTS": str(d)})
    return re.sub(r"\x1b\[[0-9;]*m", "", r.stdout)


def test_url_admin_nommee(tmp_path):
    assert _status(tmp_path, 'SECUBOX_HOSTNAME="gk7"\nSECUBOX_DOMAIN_SUFFIX="secubox.in"\n', True, True, "--url-admin").strip() == "https://admin.gk7.secubox.in/"


def test_url_admin_sans_nom_par_ip(tmp_path):
    assert _status(tmp_path, 'SECUBOX_HOSTNAME=""\n', True, True, "--url-admin").strip() == "https://192.168.1.42/"


def test_status_teste_l_agregateur_et_plus_le_hub(tmp_path):
    out = _status(tmp_path, 'SECUBOX_HOSTNAME="gk7"\n')
    assert "secubox-aggregator" in out and "(hub, API)" in out
    assert "secubox-hub" not in out and "9443" not in out
    assert "https://admin.gk7.secubox.in/" in out


def test_status_agregateur_muet(tmp_path):
    assert "ne répond pas" in _status(tmp_path, "", True, False)


def test_status_agregateur_arrete(tmp_path):
    assert "secubox-aggregator (stopped)" in _status(tmp_path, "", False, False)


def test_status_livre_par_core():
    assert "usr/bin/secubox-status" in (RACINE / "packages" / "secubox-core" / "debian" / "rules").read_text()


@pytest.mark.parametrize("image", IMAGES, ids=lambda p: p.name)
def test_images_copient_la_source_unique(image):
    t = image.read_text()
    assert "STATUS_SCRIPT" not in t
    assert "packages/secubox-core/usr/bin/secubox-status" in t
    assert not [l for l in t.splitlines() if ":9443" in l and not l.lstrip().startswith("#")]


@pytest.mark.parametrize("image", IMAGES[:2], ids=lambda p: p.name)
def test_images_console_utf8_sans_autologin_root_a_l_ecran(image):
    t = image.read_text()
    assert 'CHARMAP="UTF-8"' in t
    # Seule la console SÉRIE (accès physique) garde un autologin ; jamais un getty@ttyN de l'écran.
    for bloc in re.findall(r'getty@tty\d\.service\.d/[^"]+" <<.*?\n(?:.*\n)*?\S*EOF|AUTOLOGIN', t):
        assert "--autologin" not in bloc
    assert "getty@tty2.service.d/autologin.conf" not in t
    assert 'getty@tty1.service.d/override.conf" <<' not in t


def _charmap(tmp_path, charmap: str, lang: str) -> str:
    etc = tmp_path / "etc" / "default"
    etc.mkdir(parents=True)
    (etc / "console-setup").write_text(f'ACTIVE_CONSOLES="/dev/tty[1-6]"\nCHARMAP="{charmap}"\n')
    (etc / "locale").write_text(f"LANG={lang}\n")
    bloc = POSTINST.read_text().split("# CONSOLE EN UTF-8 (#3412)")[1].split("\n", 1)[1]
    bloc = bloc.replace("/etc/default/", f"{etc}/").replace("[ -d /run/systemd/system ]", "false")
    subprocess.run(["sh", "-c", 'set -- configure\n' + bloc], check=True, capture_output=True)
    return (etc / "console-setup").read_text()


def test_postinst_passe_la_console_en_utf8(tmp_path):
    assert 'CHARMAP="UTF-8"' in _charmap(tmp_path, "ISO-8859-15", "fr_FR.UTF-8")


@pytest.mark.parametrize("charmap,lang", [("ISO-8859-15", "fr_FR@euro"), ("KOI8-R", "ru_RU.UTF-8")])
def test_postinst_ne_touche_pas_le_reste(tmp_path, charmap, lang):
    assert f'CHARMAP="{charmap}"' in _charmap(tmp_path, charmap, lang)
