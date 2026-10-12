# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Paquet secubox-kiosk (ref #2504) : `apt-get install secubox-kiosk` doit livrer l'outil d'installation du kiosque.

Avant, secubox-kiosk-setup vivait dans image/sbin/ et seul build-image.sh le copiait : une box déjà flashée n'avait pas l'outil."""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
PAQUET = RACINE / "packages" / "secubox-kiosk"


def test_l_outil_vit_dans_le_paquet_et_plus_dans_l_image():
    assert (PAQUET / "sbin" / "secubox-kiosk-setup").is_file()
    assert not (RACINE / "image" / "sbin" / "secubox-kiosk-setup").exists(), "une seule copie"


def test_le_script_est_valide_et_executable():
    s = PAQUET / "sbin" / "secubox-kiosk-setup"
    assert s.stat().st_mode & 0o111
    assert subprocess.run(["bash", "-n", str(s)]).returncode == 0


def test_control_conforme():
    c = (PAQUET / "debian" / "control").read_text()
    assert "Package: secubox-kiosk" in c
    assert "Standards-Version: 4.6.2" in c and "debhelper-compat (= 13)" in c
    assert "Architecture: all" in c


def test_le_lanceur_vient_de_premier_pas_et_n_est_pas_livre_deux_fois():
    """L'unité générée par secubox-kiosk-setup appelle /usr/sbin/secubox-kiosk-launcher, que livre déjà secubox-premier-pas : en dépendre,
    ne pas le livrer (conflit de fichier sinon)."""
    c = (PAQUET / "debian" / "control").read_text()
    assert re.search(r"^Depends:.*secubox-premier-pas", c, re.M | re.S)
    rules = (PAQUET / "debian" / "rules").read_text()
    assert "secubox-kiosk-launcher" not in rules


def test_rules_installe_l_outil_dans_usr_sbin():
    rules = (PAQUET / "debian" / "rules").read_text()
    assert re.search(r"install -D -m 755 sbin/secubox-kiosk-setup .*usr/sbin/secubox-kiosk-setup", rules)


def test_changelog_en_tete():
    t = (PAQUET / "debian" / "changelog").read_text()
    assert re.match(r"secubox-kiosk \(1\.0\.0-1~bookworm1\) bookworm; urgency=medium", t)


def test_les_constructeurs_d_image_pointent_sur_la_nouvelle_source():
    for nom in ("build-image.sh", "build-live-usb.sh"):
        t = (RACINE / "image" / nom).read_text()
        assert "packages/secubox-kiosk/sbin" in t, nom
