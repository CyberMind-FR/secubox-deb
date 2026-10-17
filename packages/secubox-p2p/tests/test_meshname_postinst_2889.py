# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2889 — une mise a jour de secubox-p2p ne rallume pas meshname.

Le service arrete volontairement (gk2, ebin) etait active et demarre a chaque
configure. Premiere installation : enable + start ; mise a jour : l'etat de
l'operateur est conserve (try-restart seulement).
"""
import os
import subprocess
from pathlib import Path

POSTINST = Path(__file__).resolve().parents[1] / "composants/meshname/debian/postinst"


def _jouer(tmp_path, *args):
    journal = tmp_path / "appels"
    faux = tmp_path / "bin"
    faux.mkdir(exist_ok=True)
    (faux / "systemctl").write_text(f'#!/bin/sh\necho "$@" >> {journal}\n')
    (faux / "systemctl").chmod(0o755)
    env = {"PATH": f"{faux}:/usr/bin:/bin"}
    r = subprocess.run(["sh", str(POSTINST), *args], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return journal.read_text().splitlines() if journal.exists() else []


def test_premiere_installation_active_et_demarre(tmp_path):
    appels = _jouer(tmp_path, "configure")
    assert "enable secubox-meshname.service" in appels
    assert "start secubox-meshname.service" in appels


def test_mise_a_jour_ne_rallume_pas(tmp_path):
    appels = _jouer(tmp_path, "configure", "1.16.2-1~trixie1")
    assert not any(a.startswith(("enable", "start", "restart")) for a in appels), appels
    assert "try-restart secubox-meshname.service" in appels
