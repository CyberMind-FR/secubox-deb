# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2332 : l'interface locale (kiosque WebUI + console TUI headless) est dans tous les profils SANS risquer l'apply : le kiosque démarre sur condition d'unité, la console seulement sans kiosque."""
import shutil
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[2]
CONSOLE = RACINE / "packages" / "secubox-console"
SENTINELLE = "/var/lib/secubox/.kiosk-enabled"


def test_le_kiosque_demarre_sur_condition_d_unite_pas_sur_un_echec():
    d = (CONSOLE / "debian" / "dropins" / "kiosk-sentinelle.conf").read_text(encoding="utf-8")
    assert f"ConditionPathExists={SENTINELLE}" in d and "[Unit]" in d


def test_la_console_ne_demarre_que_sans_kiosque():
    d = (CONSOLE / "debian" / "dropins" / "console-sans-kiosque.conf").read_text(encoding="utf-8")
    assert f"ConditionPathExists=!{SENTINELLE}" in d


def test_le_paquet_console_installe_les_deux_dropins():
    r = (CONSOLE / "debian" / "rules").read_text(encoding="utf-8")
    assert "secubox-kiosk.service.d/10-sentinelle.conf" in r and "secubox-console.service.d/10-sans-kiosque.conf" in r


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze absent")
def test_systemd_evalue_les_deux_conditions_comme_prevu(tmp_path):
    sentinelle = tmp_path / ".kiosk-enabled"

    def ok(cond):
        return subprocess.run(["systemd-analyze", "condition", cond], capture_output=True, text=True).returncode == 0
    kiosque, console = f"ConditionPathExists={sentinelle}", f"ConditionPathExists=!{sentinelle}"
    assert not ok(kiosque) and ok(console)             # box sans tête : le kiosque est IGNORÉ, la console prend la tty1
    sentinelle.write_text("")
    assert ok(kiosque) and not ok(console)             # box avec écran : le kiosque tourne, la console reste éteinte


def test_le_kiosque_n_a_plus_d_echec_de_sentinelle_dans_les_dropins():
    for f in (CONSOLE / "debian" / "dropins").glob("*.conf"):
        actives = [l for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.lstrip().startswith("#")]      # les commentaires expliquent l'ancien test, ils ne comptent pas
        assert not any("exit 1" in l or "ExecStartPre" in l for l in actives)
