# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Le rapport WAF quotidien exige fpdf2. Debian 13 ne connaît pas `python3-fpdf2` : le paquet y est `python3-fpdf` (2.8.3).

Constaté sur gk2 après la migration : « No module named 'fpdf' », le rapport échouait chaque jour (05:38)."""
import re
from pathlib import Path

CONTROL = (Path(__file__).resolve().parents[1] / "debian" / "control").read_text()


def test_la_recommandation_de_fpdf_se_resout_sur_debian_13():
    recommande = re.search(r"(?ms)^Recommends:(.*?)^[A-Z]", CONTROL).group(1)
    assert re.search(r"python3-fpdf2\s*\|\s*python3-fpdf \(>= 2\)", recommande), recommande


def test_matplotlib_reste_recommande():
    assert "python3-matplotlib" in CONTROL
