# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_fleet_menu.py
Menu.d entry + /fleet panel coverage (Task 5, feat/fleet-metrics).

The panel is XSS-STRICT (stricter than sibling panels like www/centers):
NO inline on*= handlers (event delegation only) AND NO innerHTML anywhere
for API-sourced data — rows are built with createElement/textContent/dataset
only. Mirrors the skin (hybrid-dark, sidebar.js, sbx_token) of
www/centers/index.html.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MENU_PATH = ROOT / "menu.d" / "595-fleet.json"
HTML_PATH = ROOT / "www" / "fleet" / "index.html"

VALID_CATEGORIES = {"auth", "wall", "boot", "mind", "root", "mesh"}


def _html() -> str:
    return HTML_PATH.read_text()


# ── menu.d/595-fleet.json ────────────────────────────────────────────────

def test_menu_valid():
    m = json.loads(MENU_PATH.read_text())
    assert m.get("category") in VALID_CATEGORIES
    assert "/fleet" in json.dumps(m)


def test_menu_has_name_and_category_keys():
    m = json.loads(MENU_PATH.read_text())
    assert m.get("name")
    assert m.get("category") == "mesh"


def test_menu_path_is_fleet():
    m = json.loads(MENU_PATH.read_text())
    assert m.get("path") == "/fleet/"


# ── panel skin / navbar ──────────────────────────────────────────────────

def test_panel_uses_shared_skin_and_sidebar():
    html = _html()
    assert '<nav class="sidebar" id="sidebar">' in html
    assert '/shared/sidebar.js' in html
    assert 'hybrid-dark' in html


def test_panel_uses_sbx_token():
    html = _html()
    assert "sbx_token" in html
    assert "localStorage.getItem('jwt_token')" not in html
    assert "localStorage.getItem('token')" not in html


def test_panel_calls_fleet_api():
    html = _html()
    assert "/api/v1/annuaire" in html
    assert "'/fleet'" in html or '"/fleet"' in html


# ── XSS-STRICT: no inline handlers, no innerHTML for API data ───────────

def test_no_inline_event_handlers():
    html = _html()
    stripped = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    stripped = re.sub(r"(?<!:)//[^\n]*", "", stripped)
    offenders = re.findall(r'\son\w+\s*=\s*"', stripped)
    assert offenders == [], f"inline event handler(s) found: {offenders}"


def test_no_innerhtml_anywhere():
    """Stricter than sibling panels: fleet rows must be built with
    createElement/textContent/dataset, never innerHTML, even escaped."""
    html = _html()
    assert "innerHTML" not in html


def test_uses_create_element_and_text_content():
    html = _html()
    assert "createElement" in html
    assert "textContent" in html


def test_uses_event_delegation_with_dataset():
    html = _html()
    assert "dataset" in html
    assert "addEventListener('click'" in html or 'addEventListener("click"' in html


# ── health / staleness rendering ──────────────────────────────────────────

def test_health_states_represented():
    html = _html()
    for state in ("down", "warn", "ok"):
        assert state in html


def test_stale_handling_present():
    html = _html()
    assert "stale" in html


def test_refresh_interval_around_10s():
    html = _html()
    assert "10000" in html or "10_000" in html


# ── graceful degradation ─────────────────────────────────────────────────

def test_fetch_is_guarded_with_try_catch():
    html = _html()
    assert "try {" in html and "catch" in html
