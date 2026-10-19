# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2928 — courbes reprend des fichiers de metrics 1.25 a 1.28 (branche deployee sur gk2) : Replaces doit couvrir ces versions."""
import re
from pathlib import Path

CTRL = (Path(__file__).resolve().parents[1] / "debian" / "control").read_text()


def test_replaces_et_breaks_couvrent_metrics_jusqu_a_1_28():
    for champ in ("Replaces", "Breaks"):
        m = re.search(rf"^{champ}: secubox-metrics \(<< ([\d.]+)~\)", CTRL, re.M)
        assert m, champ
        assert tuple(int(x) for x in m.group(1).split(".")) >= (1, 29, 0), (champ, m.group(1))
