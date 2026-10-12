# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Image RPi400 (ref #2499) : l'image doit porter SON resolv.conf, pas celui de la machine de construction.

build-image.sh le fait depuis #1294 ; build-rpi-usb.sh ne le faisait pas : sur la carte, apt ne résolvait rien."""
import re
from pathlib import Path

IMAGE = Path(__file__).resolve().parents[1] / "image"


def _ecrit_resolv(script: str) -> str:
    texte = (IMAGE / script).read_text()
    m = re.search(r"cat > \"\$\{ROOTFS\}/etc/resolv\.conf\" <<'(\w+)'\n(.*?)\n\1\n", texte, re.S)
    assert m, f"{script} n'écrit pas ${{ROOTFS}}/etc/resolv.conf"
    return m.group(2)


def test_rpi_ecrit_son_resolv_conf():
    contenu = _ecrit_resolv("build-rpi-usb.sh")
    serveurs = re.findall(r"^nameserver (\S+)", contenu, re.M)
    assert serveurs[0] == "127.0.0.1"
    assert len(serveurs) >= 2, "il faut un filet public pour l'amorçage"
    assert "127.0.0.53" not in contenu


def test_rpi_resolv_conf_ecrit_avant_la_fin_du_chroot():
    texte = (IMAGE / "build-rpi-usb.sh").read_text()
    assert texte.index("/etc/resolv.conf") < texte.index('log "7/7 Creating bootable image')


def test_rpi_et_serveur_ont_le_meme_resolv_conf():
    assert _ecrit_resolv("build-rpi-usb.sh") == _ecrit_resolv("build-image.sh")
