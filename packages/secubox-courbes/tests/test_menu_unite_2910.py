# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2910 — Courbes et Glances sont jugees sur courbes.sock, pas sur l'id de leur page (ref #2905)."""
import json
from pathlib import Path

MENU = Path(__file__).resolve().parents[1] / "menu.d"


def test_les_deux_pages_portent_unite_courbes():
    for nom in ("50-grafana.json", "904-glances.json"):
        assert json.loads((MENU / nom).read_text()).get("unite") == "courbes", nom
