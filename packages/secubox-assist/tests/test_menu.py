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


def test_panel_has_marketplace_tab_hooks():
    html = (ROOT / "www" / "assist" / "index.html").read_text()
    # no inline handlers anywhere, even in the new tabs
    assert "onclick=" not in html
    assert "onsubmit=" not in html
    # event-delegated data-act hooks for the 5 marketplace tabs: static buttons
    # carry a literal data-act="..." attribute; per-item (dynamic) buttons are
    # built in JS and assigned dataset.act from a matching string literal.
    for act in ("offer", "offer-revoke", "request-open", "match-accept", "joinlink"):
        assert f'data-act="{act}"' in html or f"'{act}'" in html
    # endpoints reachable from the panel
    for path in ("/api/v1/assist/offers", "/api/v1/assist/requests/open",
                 "/api/v1/assist/matches", "/api/v1/assist/offer",
                 "/api/v1/assist/request/open", "/api/v1/assist/match/accept",
                 "/api/v1/assist/joinlink"):
        assert path in html
    # XSS guard: dynamic rendering must never use innerHTML string building
    assert "innerHTML" not in html


def test_panel_pending_list_has_readable_empty_state_not_raw_json():
    html = (ROOT / "www" / "assist" / "index.html").read_text()
    # the pending-requests card must no longer dump a raw JSON array
    assert "JSON.stringify(d.pending" not in html
    # readable empty-state text present
    assert "Aucune demande en attente" in html
    # section header reflects what it actually shows (pending requests, not a log)
    assert "Demandes en attente" in html


def test_panel_clarifies_targeted_vs_open_request():
    html = (ROOT / "www" / "assist" / "index.html").read_text()
    assert "Requête ciblée" in html
    assert "Requête ouverte" in html
