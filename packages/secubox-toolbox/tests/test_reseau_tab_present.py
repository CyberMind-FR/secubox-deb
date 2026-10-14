# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""The Réseau tab is wired into the toolbox dashboard (ref #758)."""
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / "www" / "toolbox" / "index.html"


def test_reseau_tab_button_panel_and_loader():
    """#2684 : la coque Aurora déclare l'onglet Réseau (page SOC encadrée) ; les routes netstats vivent dans l'onglet Vue d'ensemble."""
    t = HTML.read_text()
    assert "['reseau'," in t and "reseau: '/soc/reseau.html'" in t
    assert 'role", "tab"' in t.replace("'", '"') or "setAttribute('role', 'tab')" in t
    apercu = (HTML.parent / "apercu.html").read_text()
    assert "netstats/summary" in apercu
    assert "netstats/series" in apercu
