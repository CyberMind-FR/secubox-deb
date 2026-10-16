# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2792 — le bloc de pastilles (live, menaces, services KO, materiel) de la barre laterale est retire sur toutes les pages."""
import re
from pathlib import Path

JS = (Path(__file__).resolve().parents[1] / "www" / "shared" / "sidebar.js").read_text(encoding="utf-8")


def test_le_bloc_est_masque_meme_depuis_le_cache_html():
    assert re.search(r"\.header-leds-metrics\s*\{[^}]*display:\s*none\s*!important", JS)


def test_plus_aucune_requete_pour_alimenter_un_bloc_invisible():
    corps = JS.split("async function loadStatusBarData() {", 1)[1][:200]
    assert corps.lstrip().startswith("return;")
