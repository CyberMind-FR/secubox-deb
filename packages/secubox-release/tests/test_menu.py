# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


VALID_CATEGORIES = {"auth", "wall", "boot", "mind", "root", "mesh"}


def test_menu_is_valid_json_with_releases_path():
    m = json.loads((ROOT / "menu.d" / "590-releases.json").read_text())
    blob = json.dumps(m)
    assert "/releases" in blob
    assert isinstance(m.get("name"), str) and m.get("name")
    assert m.get("category") in VALID_CATEGORIES


def test_panel_uses_sbx_token_and_sidebar_js():
    html = (ROOT / "www" / "releases" / "index.html").read_text()
    assert "sbx_token" in html
    assert "/shared/sidebar.js" in html


def test_panel_has_no_inline_onclick_or_innerhtml():
    html = (ROOT / "www" / "releases" / "index.html").read_text()
    assert "onclick=" not in html
    assert "innerHTML" not in html


def test_panel_has_promote_demote_assign_hooks():
    html = (ROOT / "www" / "releases" / "index.html").read_text()
    # promote/demote rows are built per-evolution via createElement + dataset
    # (no innerHTML allowed), so the hook shows as a dataset.act assignment;
    # assign/publish are static buttons with a literal data-act attribute.
    assert "dataset.act = 'promote'" in html
    assert "dataset.act = 'demote'" in html
    assert 'data-act="assign"' in html
    assert 'data-act="publish"' in html
