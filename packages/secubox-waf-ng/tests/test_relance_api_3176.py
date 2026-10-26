# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3176 : une mise à jour de waf-ng ne rechargeait jamais l'API du WAF. Le postinst du composant faisait `systemctl start
secubox-waf.service` (rien sur un service qui tourne) et ni le prerm ni dh_installsystemd ne le touchent : sur gk2, 1.30.4
installée, l'API servait encore le code du 24/10 (blocked_24h = journal depuis la rotation, sans menaces_24h)."""
import subprocess
from pathlib import Path

POSTINST = Path(__file__).resolve().parents[1] / "composants" / "waf" / "debian" / "postinst"


def _appels(tmp_path, *args):
    """Exécute le postinst avec un faux `systemctl` (et des chown/chmod/nginx inertes) ; rend les appels à systemctl."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    journal = tmp_path / "appels"
    for outil in ("systemctl", "chown", "chmod", "nginx", "install", "ln", "mkdir", "getent", "adduser", "usermod", "id", "rm", "cp", "sed"):
        f = bin_ / outil
        f.write_text(f'#!/bin/sh\necho "{outil} $*" >> "{journal}"\nexit 0\n')
        f.chmod(0o755)
    subprocess.run(["sh", str(POSTINST), *args], env={"PATH": f"{bin_}:/usr/bin:/bin"}, cwd=tmp_path, capture_output=True, timeout=60)
    return [l for l in journal.read_text().splitlines() if l.startswith("systemctl ")] if journal.exists() else []


def test_une_mise_a_jour_relance_l_api(tmp_path):
    assert "systemctl restart secubox-waf.service" in _appels(tmp_path, "configure", "1.30.3-1~trixie1")


def test_une_premiere_installation_la_demarre(tmp_path):
    appels = _appels(tmp_path, "configure", "")
    assert "systemctl start secubox-waf.service" in appels and "systemctl restart secubox-waf.service" not in appels
