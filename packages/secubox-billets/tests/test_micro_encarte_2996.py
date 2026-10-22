# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — encarté par le Hall v2 ({sbx:'carte'}), le micro des billets range sa marque (icône, titre) : la Card la porte déjà."""
from pathlib import Path

API = Path(__file__).resolve().parents[1] / "api"
MICRO = (API / "templates" / "micro.html").read_text(encoding="utf-8")
CSS = (API / "static" / "micro.css").read_text(encoding="utf-8")


def test_le_micro_ecoute_carte_et_range_sa_marque():
    assert "d.sbx==='carte'" in MICRO and "classList.add('sbx-carte')" in MICRO
    assert "html.sbx-carte .tete .ic, html.sbx-carte .tete b { display:none; }" in CSS
