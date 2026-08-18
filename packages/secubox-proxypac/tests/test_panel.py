# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# packages/secubox-proxypac/tests/test_panel.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def test_panel_has_navbar_and_status_and_runbook():
    h = (ROOT/"www/proxypac/index.html").read_text()
    assert 'class="sidebar"' in h and '/shared/sidebar.js' in h, "navbar manquante"
    assert '/api/v1/proxypac/status' in h, "carte statut manquante"
    assert 'socks_remote_dns' in h, "runbook client manquant"
    assert 'sbx_token' in h, "doit lire le jeton sbx_token"
    assert '/transparent' in h, "toggle transparent manquant"

def test_menu_entry_valid_json():
    import json
    j = json.loads((ROOT/"menu.d/580-proxypac.json").read_text())
    assert j["path"] == "/proxypac/" and j["id"] == "proxypac"

def test_no_inline_handler_interpolates_dynamic_data():
    # Régression XSS stockée : aucun handler inline (onclick/onchange/...) ne doit
    # interpoler une donnée d'API (host, directive, candidat...) via un template
    # `${...}`. Un attribut HTML échappé (esc()) est décodé par le navigateur
    # AVANT que le contenu de l'attribut d'événement soit traité comme du JS,
    # ce qui permet une évasion de chaîne (ex: host = "x');alert(1);//").
    # La donnée dynamique doit être portée par un data-* attribut et lue via
    # un listener délégué (event delegation), jamais interpolée dans le JS inline.
    h = (ROOT/"www/proxypac/index.html").read_text()
    import re
    for m in re.finditer(r'on(click|change|input|submit)\s*=\s*(["\'])(.*?)\2', h, re.S):
        assert '${' not in m.group(3), f"handler inline interpole une donnée: {m.group(0)[:80]}"
