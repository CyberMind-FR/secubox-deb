# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# packages/secubox-proxypac/tests/test_webui_panel.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_panel_calls_api_and_has_override_form():
    html = (ROOT / "www" / "proxypac" / "index.html").read_text()
    assert "/api/v1/proxypac/rules" in html
    assert "/api/v1/proxypac/override" in html
    assert 'id="host"' in html and 'id="proxy"' in html

def test_menu_entry_points_to_panel():
    import json
    m = json.loads((ROOT / "menu.d" / "580-proxypac.json").read_text())
    assert m.get("path") == "/proxypac/" or m.get("url") == "/proxypac/"
    assert m.get("name") == "ProxyPAC"
    assert m.get("category") in ("auth","wall","boot","mind","root","mesh")
