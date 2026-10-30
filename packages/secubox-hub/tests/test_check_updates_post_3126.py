# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 (R-L5-17 M2) : `check_updates` lance `apt update` : une action, jamais servie en GET (portée lecture déléguée)."""
import re
from pathlib import Path

MAIN = Path(__file__).resolve().parents[1] / "api" / "main.py"


def test_check_updates_en_post_seulement():
    source = MAIN.read_text(encoding="utf-8")
    assert re.search(r'@router\.post\("/check_updates"\)', source)
    assert not re.search(r'@router\.get\("/check_updates"\)', source)
