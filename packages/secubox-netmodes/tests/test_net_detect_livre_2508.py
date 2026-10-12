# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-net-detect livré par secubox-netmodes (ref #2508).

L'assistant premier-pas appelle `secubox-net-detect apply <mode>` : sur l'image RPi400 l'outil n'existait pas (code 127), faute de paquet
qui le livre — il vivait dans image/sbin/ et seuls certains constructeurs d'image le copiaient."""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
PAQUET = RACINE / "packages" / "secubox-netmodes"


def test_l_outil_est_dans_le_paquet_une_seule_copie():
    assert (PAQUET / "sbin" / "secubox-net-detect").is_file()
    assert not (RACINE / "image" / "sbin" / "secubox-net-detect").exists()


def test_script_valide_et_executable():
    s = PAQUET / "sbin" / "secubox-net-detect"
    assert s.stat().st_mode & 0o111
    assert subprocess.run(["bash", "-n", str(s)]).returncode == 0


def test_rules_installe_dans_usr_sbin():
    rules = (PAQUET / "debian" / "rules").read_text()
    assert re.search(r"install -m 0755 sbin/secubox-net-detect debian/secubox-netmodes/usr/sbin/", rules)


def test_le_constructeur_live_la_prend_dans_le_paquet():
    t = (RACINE / "image" / "build-live-usb.sh").read_text()
    assert "packages/secubox-netmodes/sbin/secubox-net-detect" in t


def test_chemin_attendu_par_premier_pas():
    m = (RACINE / "packages" / "secubox-premier-pas" / "premier_pas" / "moteur.py").read_text()
    assert 'NET_DETECT = Path("/usr/sbin/secubox-net-detect")' in m
