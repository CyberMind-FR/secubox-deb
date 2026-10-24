# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2830 — retirer secubox-webos retire le lien d'activation que SON postinst a pose.

Constate sur l'ESPRESSObin : `dpkg --purge secubox-webos` laissait /etc/nginx/sites-enabled/hall.gk2.net.conf -> ../sites-available/... (casse) ;
`nginx -t` echouait (open() failed) et le rechargement etait refuse."""
import subprocess
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
POSTRM = PKG / "debian" / "postrm"


def test_un_postrm_existe_et_garde_le_jeton_debhelper():
    s = POSTRM.read_text()
    assert s.startswith("#!/bin/sh") and "#DEBHELPER#" in s, "sans le jeton, le dpkg-maintscript-helper du .maintscript disparait"


def test_le_lien_d_activation_est_retire_a_remove_et_purge():
    s = POSTRM.read_text()
    assert "remove" in s and "purge" in s and "/etc/nginx/sites-enabled/hall.conf" in s
    assert "rm -f /etc/nginx/sites-enabled/hall.conf" in s


def test_seul_un_lien_est_retire_jamais_un_fichier_reel():
    """Un fichier ordinaire posé là par l'opérateur n'est pas le nôtre."""
    s = POSTRM.read_text()
    assert '[ -L /etc/nginx/sites-enabled/hall.conf ]' in s


def test_le_script_est_du_sh_valide():
    assert subprocess.run(["sh", "-n", str(POSTRM)], capture_output=True).returncode == 0
