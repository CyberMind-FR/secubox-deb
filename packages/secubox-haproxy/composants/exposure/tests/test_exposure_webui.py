# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_panel_calls_exposure_api_with_reach_options():
    html = (ROOT / "www" / "exposure" / "index.html").read_text()
    assert "/api/v1/exposure/" in html
    for v in ("localhost", "lan", "wan"):
        assert v in html
    assert "mesh" in html and "tor" in html.lower()
