# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3891 : une page oubliée ouverte interrogeait gk2 toutes les 2,5 s. Le menu latéral relit la LED toutes les 15 s, jamais
onglet caché ; la carte Lyrion du Hall ne relit le lecteur que si l'onglet est visible."""
import re
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]


def test_led_du_menu_15_s_et_jamais_onglet_cache():
    src = (PAQUETS / "secubox-hub" / "www" / "shared" / "sidebar.js").read_text(encoding="utf-8")
    f = src[src.index("async function fetchHardwareLedStatus()"):src.index("function startLedStatusRefresh()")]
    assert "document.hidden" in f
    demarre = src[src.index("function startLedStatusRefresh()"):]
    demarre = demarre[:demarre.index("\n    }\n")]
    assert "setInterval(fetchHardwareLedStatus, 15000)" in demarre and "visibilitychange" in demarre
    assert not re.search(r"setInterval\(fetchHardwareLedStatus,\s*5000\)", src)


def test_carte_lyrion_ne_releve_pas_onglet_cache():
    src = (PAQUETS / "secubox-webos" / "www" / "hall" / "cardlets" / "lyrion.html").read_text(encoding="utf-8")
    for bloc in re.findall(r"setInterval\(function \(\) \{(.*?)\}, \d+\);", src):
        assert "document.hidden" in bloc, bloc
