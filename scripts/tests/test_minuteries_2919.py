# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2919 — aucune minuterie du depot n'a le motif « OnUnitActiveSec » nu.

Une minuterie qui n'a que OnBootSec + OnUnitActiveSec ne se redeclenche plus apres une reactivation faite
apres le demarrage (mise a jour de son paquet) : collecte netstats figee depuis le 14/10 et minuteries annuaire
depuis le 5/10 sur gk2. OnActiveSec compte depuis l'activation de la minuterie."""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]


def _minuteries():
    r = subprocess.run(["git", "-C", str(RACINE), "ls-files", "*.timer"], capture_output=True, text=True, check=True)
    return [RACINE / p for p in r.stdout.split() if not re.search(r"/debian/[^/]+/", p)]   # pas les arbres de construction


def test_au_moins_une_minuterie_est_examinee():
    assert len(_minuteries()) > 60


def test_pas_de_onunitactivesec_nu():
    nues = []
    for t in _minuteries():
        txt = t.read_text()
        if re.search(r"^OnUnitActiveSec=\S", txt, re.M) and not re.search(r"^(OnActiveSec|OnCalendar|OnUnitInactiveSec)=\S", txt, re.M):
            nues.append(str(t.relative_to(RACINE)))
    assert not nues, f"{len(nues)} minuteries sans declencheur depuis l'activation : {nues[:8]}"
