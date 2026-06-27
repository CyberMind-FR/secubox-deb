# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""The Réseau tab is wired into the toolbox dashboard (ref #758)."""
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / "www" / "toolbox" / "index.html"


def test_reseau_tab_button_panel_and_loader():
    t = HTML.read_text()
    assert 'data-tab="reseau"' in t
    assert 'id="panel-reseau"' in t
    assert "loadNetstats" in t
    # talks to the hub netstats endpoints
    assert "/api/v1/hub/netstats/summary" in t
    assert "/api/v1/hub/netstats/series" in t
