# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_centers_panel.py
WebUI panel /centers (Task 9, feat/centers-grants-remote-config): ownership
matrix (scope x layer -> owner), grant/revoke controls, proposals (un-granted
pushes), effective-vs-local diff — plus the navbar/token conventions and the
hardened XSS-delegation guard.

The mutating /centers/* endpoints (Task 8, api/main.py) are JWT-gated —
unlike the pre-existing www/annuaire/index.html panel, which never sends a
token — so every fetch here MUST attach 'Authorization: Bearer ' + sbx_token.

XSS guard: reuses the hardened form from
secubox-toolbox/tests/test_rlevel_panel.py::test_no_inline_handler_interpolates_api_data
(post-proxypac-lesson) — strips comments, then flags ANY non-whitelisted
inline on*="..." handler, not just one containing `${`, so it also catches
string concatenation (`'` + var + `'`) offenders.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "www" / "centers" / "index.html"
MENU_PATH = ROOT / "menu.d" / "570-centers.json"


def _html() -> str:
    return HTML_PATH.read_text()


# ── navbar / shared skin ────────────────────────────────────────────────

def test_sidebar_and_shared_assets_present():
    html = _html()
    assert '<nav class="sidebar" id="sidebar">' in html
    assert '/shared/sidebar.js' in html
    assert 'hybrid-dark.css' in html or 'hybrid-skin.css' in html
    assert 'hybrid-dark' in html  # body class or palette reference


# ── auth token convention ────────────────────────────────────────────────

def test_uses_sbx_token_bearer_and_same_origin_credentials():
    html = _html()
    assert "sbx_token" in html
    assert "'Bearer ' +" in html or '"Bearer " +' in html
    assert "credentials:" in html and "same-origin" in html
    # must not read any other localStorage key as the token
    assert "localStorage.getItem('jwt_token')" not in html
    assert "localStorage.getItem('token')" not in html


# ── API contract (task 8) ────────────────────────────────────────────────

def test_calls_centers_ownership():
    html = _html()
    assert "/centers/ownership" in html


def test_calls_centers_list():
    html = _html()
    assert "API + '/centers'" in html or '"/centers"' in html or "'/centers'" in html


def test_calls_centers_proposals():
    html = _html()
    assert "/centers/proposals" in html


def test_calls_centers_effective_scope():
    html = _html()
    assert "/centers/effective/" in html


def test_calls_centers_grant_post_with_body_fields():
    html = _html()
    assert "/centers/grant" in html
    assert "method: 'POST'" in html or 'method:"POST"' in html or "method:'POST'" in html
    assert "center_did" in html
    assert "scope" in html
    assert "layer" in html


def test_calls_centers_revoke_post_with_grant_id_in_body():
    html = _html()
    assert "/centers/revoke" in html
    assert "grant_id" in html
    # grant_id must travel in the JSON body, never interpolated into the URL
    assert "/centers/revoke/" not in html


def test_calls_proposal_accept_post():
    html = _html()
    assert "/centers/proposal/accept" in html


# ── ownership matrix (scope x layer) ─────────────────────────────────────

def test_ownership_matrix_has_three_layer_columns():
    html = _html()
    for layer in ("baseline", "override", "local"):
        assert layer in html


def test_grant_revoke_controls_present():
    html = _html()
    assert "revoke" in html.lower() or "révoqu" in html.lower()
    assert "grant" in html.lower() or "accord" in html.lower()


# ── proposals section ─────────────────────────────────────────────────────

def test_proposals_section_present():
    html = _html()
    assert "proposal" in html.lower() or "proposition" in html.lower()


# ── effective diff ────────────────────────────────────────────────────────

def test_effective_diff_shows_effective_and_local():
    html = _html()
    assert "effective" in html.lower()
    assert "local" in html.lower()


# ── XSS guard — CRITICAL (proxypac lesson, hardened per rlevel) ──────────

def test_no_inline_handler_interpolates_api_data():
    """No on*="...${...}..." handler anywhere — API-sourced values (scope,
    center_did, grant_id) must never be spliced into an inline event-handler
    string. Row/card actions must use data-* attributes + a delegated
    listener instead.

    Whitelist of the SEULS handlers inline statiques autorisés (aucune
    donnée d'API). Tout autre handler inline — interpolation `${...}` OU
    concaténation `'`+var+`'` OU toute variable — est un offender.
    """
    html = _html()
    # Retire les commentaires (HTML + JS de ligne) pour ne pas flaguer une
    # DOC qui mentionne onclick="..." ; le (?<!:) préserve http://.
    stripped = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    stripped = re.sub(r"(?<!:)//[^\n]*", "", stripped)
    ALLOWED_STATIC = {"loadAll()", "loadOwnership()"}
    offenders = [
        m.group(0)
        for m in re.finditer(r'\son\w+\s*=\s*"([^"]*)"', stripped)
        if m.group(1).strip() not in ALLOWED_STATIC
    ]
    assert offenders == [], f"inline handler non-statique (utilise data-*+délégation): {offenders}"


def test_uses_event_delegation_with_dataset():
    html = _html()
    assert "dataset" in html
    assert "addEventListener('click'" in html or 'addEventListener("click"' in html
    # scope/center_did/grant_id must travel via data-* attributes
    assert "data-scope" in html
    assert "data-center-did" in html or "data-center_did" in html


def test_esc_helper_defined_and_used():
    html = _html()
    assert "function esc(" in html
    assert "esc(" in html.split("function esc(", 1)[1]  # used somewhere after definition


# ── graceful degradation ─────────────────────────────────────────────────

def test_fetches_are_guarded_with_try_catch():
    html = _html()
    assert "try {" in html and "catch" in html


# ── menu.d entry ──────────────────────────────────────────────────────────

def test_menu_entry_valid_json_with_required_fields():
    entry = json.loads(MENU_PATH.read_text())
    assert entry["id"] == "centers"
    assert entry["name"]
    assert entry["path"] == "/centers/"
    assert entry["icon"]
    assert entry["order"] == 570
