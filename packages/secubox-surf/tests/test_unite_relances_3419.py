# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3419 — secubox-surf : relances bornées, jamais une boucle sans fin au premier démarrage."""
import re
from pathlib import Path

UNIT = (Path(__file__).resolve().parents[1] / "systemd" / "secubox-surf.service").read_text()


def _val(cle):
    return int(re.search(rf"^{cle}=(\d+)$", UNIT, re.M).group(1))


def test_limite_de_relances_atteignable():
    assert _val("StartLimitBurst") * _val("RestartSec") < _val("StartLimitIntervalSec")
    unit_section = UNIT.split("[Service]", 1)[0]
    assert "StartLimitBurst" in unit_section and "StartLimitIntervalSec" in unit_section
