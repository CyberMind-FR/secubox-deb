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


def test_la_barre_du_bas_reste_alimentee_2887():
    """#2887 : loadStatusBarData alimente la barre d'etat du BAS (sante, Mode,
    Auth, CPU, MEM, DISK, Uptime), pas le bloc de pastilles retire. Un return en
    tete la laissait a « -- » sur toutes les boxes."""
    corps = JS.split("async function loadStatusBarData() {", 1)[1]
    assert not corps.lstrip().startswith("return;")
    assert "/api/v1/hub/dashboard" in corps[:1500]
    assert "gsb-uptime" in corps[:1500]
