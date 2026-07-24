# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""WebUI panel /rlevel (task 7, #rlevel-per-peer): peer table with effective-mode
badges, admin floor/force controls, peer self-service — plus the navbar/token
conventions and the XSS-delegation guard (proxypac lesson: never interpolate
API-sourced data — pubkey, label — into an inline `onclick="..."` string).
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "www" / "rlevel" / "index.html"
MENU_PATH = ROOT / "menu.d" / "27-rlevel.json"


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


# ── API contract (task 6) ────────────────────────────────────────────────

def test_calls_admin_peers_list():
    html = _html()
    assert "/rlevel/peers" in html


def test_calls_admin_peer_post_with_pubkey_in_body():
    html = _html()
    assert "/rlevel/peer'" in html or '/rlevel/peer"' in html
    assert "method: 'POST'" in html or 'method:"POST"' in html or "method:'POST'" in html
    # pubkey must travel in the JSON body, never interpolated into the URL
    assert "/rlevel/peer/" not in html
    assert "pubkey" in html


def test_calls_self_service_me_get_and_post():
    html = _html()
    assert "/rlevel/me" in html
    assert "chosen" in html


# ── mode badges (4 distinct) ─────────────────────────────────────────────

def test_four_mode_badges_present_and_distinctly_colored():
    html = _html()
    for mode in ("off", "passive", "active", "reel"):
        assert re.search(r'badge-' + mode + r'\b', html), f"missing badge-{mode} class"
    # pull out the 4 badge color declarations and assert they're distinct
    colors = re.findall(r'\.badge-(?:off|passive|active|reel)\s*\{[^}]*color:\s*([^;]+);', html)
    assert len(colors) >= 4
    assert len(set(colors)) == len(colors), f"badge colors not all distinct: {colors}"


# ── admin controls: floor + force/unlock ─────────────────────────────────

def test_admin_floor_and_force_controls_present():
    html = _html()
    assert "floor" in html
    assert "forced" in html
    # a control to clear/unlock a forced mode
    assert "force" in html.lower()


# ── self-service control ─────────────────────────────────────────────────

def test_self_service_chosen_control_present():
    html = _html()
    assert "rlevel/me" in html
    assert "chosen" in html


# ── XSS guard — CRITICAL (proxypac lesson) ───────────────────────────────

def test_no_inline_handler_interpolates_api_data():
    """No on*="...${...}..." handler anywhere — API-sourced values (pubkey,
    label) must never be spliced into an inline event-handler string. Row/card
    actions must use data-* attributes + a delegated listener instead."""
    html = _html()
    offenders = [
        m.group(0) for m in re.finditer(r'on\w+\s*=\s*["\'][^"\']*["\']', html)
        if '${' in m.group(0)
    ]
    assert offenders == [], f"inline handler interpolates data: {offenders}"


def test_uses_event_delegation_with_dataset():
    html = _html()
    assert "data-pubkey" in html
    assert "dataset" in html
    assert "addEventListener('click'" in html or 'addEventListener("click"' in html


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
    assert entry["id"] == "rlevel"
    assert entry["name"]
    assert entry["path"] == "/rlevel/"
    assert entry["icon"]
    assert entry["order"] != 26  # distinct from toolbox's own entry
