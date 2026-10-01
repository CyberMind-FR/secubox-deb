# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""firstboot met la box neuve derrière HAProxy + sbxwaf (#1845).

On exécute l'étape 16 telle qu'écrite, sous `set -euo pipefail` comme
firstboot, avec des doublures : un refus de `haproxyctl frontal` ne doit pas
interrompre le premier démarrage, et l'étape vient après le pare-feu.
"""
import os
import subprocess
from pathlib import Path

import pytest

FIRSTBOOT = Path(__file__).resolve().parents[2] / "image" / "firstboot.sh"


def _etape16() -> str:
    s = FIRSTBOOT.read_text(encoding="utf-8")
    debut = s.index("# ── 16. Frontal HAProxy")
    fin = s.index('log "=== First boot terminé ==="', debut)
    return s[debut:fin]


def test_etape_apres_le_pare_feu_et_avant_la_fin():
    s = FIRSTBOOT.read_text(encoding="utf-8")
    assert s.index("# ── 12. nftables") < s.index("# ── 16. Frontal HAProxy") < s.index('log "=== First boot terminé ==="')


@pytest.mark.parametrize("code_frontal,attendu", [(0, "Frontal HAProxy + sbxwaf actif"),
                                                  (1, "nginx autonome conservé")])
def test_refus_du_frontal_non_fatal(tmp_path, code_frontal, attendu):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    journal = tmp_path / "appels"
    for nom, corps in (
        ("haproxyctl", f'echo "haproxyctl $*" >> {journal}; exit {code_frontal}'),
        ("secubox-defaults-aligner", f'echo aligner >> {journal}'),
        ("ss", 'echo "LISTEN 0 4096 127.0.0.1:8085 0.0.0.0:*"'),
        ("sleep", "exit 0"),
    ):
        f = bin_ / nom
        f.write_text("#!/bin/sh\n" + corps + "\n")
        f.chmod(0o755)
    script = ("set -euo pipefail\nlog() { echo \"LOG $*\"; }\nok() { echo \"OK $*\"; }\n"
              + _etape16() + "\necho FIN\n")
    p = subprocess.run(["bash", "-c", script], env=dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}"),
                       capture_output=True, text=True)
    assert p.returncode == 0 and "FIN" in p.stdout and attendu in p.stdout, p.stdout + p.stderr
    assert journal.read_text().splitlines() == ["aligner", "haproxyctl frontal"]
