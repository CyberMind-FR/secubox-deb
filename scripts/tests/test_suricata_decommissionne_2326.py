# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2326 : Suricata est décommissionné. Aucune intégration ne réapparaît dans le code, les unités, les paquets ni les scripts d'image (les specs et plans historiques ne sont pas réécrits)."""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
# Documents d'histoire ou de conception future : conservés tels quels.
EXCLUS = ("docs/", ".claude/", "doctrine/", "cache/", "packages/secubox-egress/", "scripts/tests/test_suricata_decommissionne_2326.py")


def _fichiers():
    sortie = subprocess.run(["git", "ls-files"], cwd=RACINE, capture_output=True, text=True, check=True).stdout.splitlines()
    for f in sortie:
        if f.startswith(EXCLUS) or f.endswith(("changelog", ".md", ".deb")) or "/debian/" in f and f.endswith(".log"):
            continue
        yield f


def test_aucune_reference_a_suricata_dans_le_code_les_unites_les_paquets_et_les_scripts():
    trouves = []
    for f in _fichiers():
        try:
            if re.search(r"suricata", (RACINE / f).read_text(encoding="utf-8", errors="ignore"), re.I):
                trouves.append(f)
        except OSError:
            continue
    assert not trouves, f"Suricata est décommissionné (#2326) : {trouves}"


def test_threats_n_a_plus_de_repertoire_de_journal_suricata_dans_son_unite():
    """Son absence provoquait le crash 226/NAMESPACE de threats (#494 bis) : l'unité ne doit plus l'exiger."""
    u = (RACINE / "packages/secubox-threats/systemd/secubox-threats.service").read_text(encoding="utf-8")
    assert "/var/log/suricata" not in u
