# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


VALID_CATEGORIES = {"auth", "wall", "boot", "mind", "root", "mesh"}


def test_menu_is_valid_json_with_assist_path():
    m = json.loads((ROOT / "menu.d" / "580-assist.json").read_text())
    blob = json.dumps(m)
    assert "/assist" in blob
    assert isinstance(m.get("name"), str) and m.get("name")
    assert m.get("category") in VALID_CATEGORIES


def test_panel_uses_sbx_token_and_no_inline_onclick():
    html = (ROOT / "www" / "assist" / "index.html").read_text()
    assert "sbx_token" in html
    assert "/shared/sidebar.js" in html
    assert "onclick=" not in html  # event delegation only
