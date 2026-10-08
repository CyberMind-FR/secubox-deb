# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le watchdog LMS ne doit pas relancer LMS en boucle (141 restarts en 3 h sur gk2).

LMS reste muet pendant son démarrage et son scan de médiathèque ; sur une box en swap,
:9000 ne répond pas dans les 4 s. Relancer LMS relance le scan : la boucle s'entretient
et prend tout le CPU. On laisse un délai de grâce, on ne relance pas pendant un scan, et
on plafonne les relances par heure."""
import os
import stat
import subprocess
import time
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-lyrion-watchdog"


def lance(tmp_path, scan=False, avant=None, journal_restarts=0):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    journal = tmp_path / "appels"

    def faux(nom, corps):
        f = bin_ / nom
        f.write_text("#!/bin/sh\n" + corps + "\n")
        f.chmod(f.stat().st_mode | stat.S_IEXEC)

    faux("lxc-info", "echo 'State:          RUNNING'")
    faux("curl", "exit 22")                       # :9000 muet
    faux("sleep", "exit 0")
    faux("pgrep", "exit 0" if scan else "exit 1")  # un scan est-il en cours ?
    faux("lxc-attach", f'echo "attach $*" >> {journal}')
    faux("lxc-stop", f'echo "stop" >> {journal}')
    faux("lxc-start", f'echo "start" >> {journal}')
    etat = tmp_path / "etat"
    etat.mkdir()
    if avant is not None:
        (etat / "restarts").write_text("\n".join(str(int(time.time() - s)) for s in avant) + "\n")
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", LYRION_ETAT=str(etat))
    r = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True)
    appels = journal.read_text() if journal.exists() else ""
    return r, appels, etat


def test_premier_muet_relance_lms_et_note_l_heure(tmp_path):
    r, appels, etat = lance(tmp_path)
    assert "restart" in appels and (etat / "restarts").exists()


def test_pas_de_relance_pendant_le_delai_de_grace(tmp_path):
    r, appels, _ = lance(tmp_path, avant=[120])         # relancé il y a 2 min : il démarre / scanne
    assert appels == "" and "grâce" in r.stdout


def test_pas_de_relance_pendant_un_scan_de_mediatheque(tmp_path):
    r, appels, _ = lance(tmp_path, scan=True)
    assert appels == "" and "scan" in r.stdout


def test_au_plus_trois_relances_par_heure(tmp_path):
    r, appels, _ = lance(tmp_path, avant=[3000, 2000, 1000])
    assert appels == "" and "plafond" in r.stdout


def test_une_relance_ancienne_ne_compte_plus(tmp_path):
    r, appels, _ = lance(tmp_path, avant=[7200, 3000, 2000, 1000][:1] + [900])
    assert "restart" in appels
