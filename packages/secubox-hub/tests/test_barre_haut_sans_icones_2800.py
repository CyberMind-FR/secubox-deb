# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2800 — le bloc de six icones (smart-strip) de la barre du haut est retire sur toutes les pages."""
import re
from pathlib import Path

JS = (Path(__file__).resolve().parents[1] / "www" / "shared" / "sidebar.js").read_text(encoding="utf-8")


def test_la_smart_strip_est_masquee():
    assert re.search(r"\.smart-strip\s*\{[^}]*display:\s*none\s*!important", JS)
