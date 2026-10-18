# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2907 — « Boxes a preparer » est juge sur l'agregateur qui sert son API, pas sur l'unite de premier demarrage."""
import json
from pathlib import Path


def test_la_page_maitre_est_jugee_sur_l_agregateur():
    d = json.loads((Path(__file__).resolve().parents[1] / "menu.d/905-premier-pas-maitre.json").read_text())
    assert d["id"] == "premier-pas-maitre" and d.get("unite") == "aggregator"
