# packages/secubox-eye-square/kiosk/tests/test_kiosk_smoke.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Smoke test for the kiosk loop — assemble all modules and render one frame.

T11 collapsed the in-package RingDashboard into a SquareDashboard subclass
of secubox_common.canvas.DashboardCanvas, so this test now drives the
unified composer (left dashboard + right panel into a single 800×480
image). The on-module-tap routing it used to cover lives in __main__.py
after T15 and is re-covered there."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

# secubox_common ships at /var/www/common/python/ on the image; for tests
# we add the dev checkout (parents[4] = repo root from this file).
_DEV = Path(__file__).resolve().parents[4] / "remote-ui" / "common" / "python"
if str(_DEV) not in sys.path:
    sys.path.insert(0, str(_DEV))

from secubox_eye_square_kiosk.right_panel import RightPanel
from secubox_eye_square_kiosk.sim import SimState, step
from secubox_eye_square_kiosk.square_dashboard import SquareDashboard
def test_compose_full_800x480_frame(tmp_path: Path):
    """End-to-end render: SquareDashboard composes dashboard + panel."""
    helper = MagicMock()
    sim = SimState()
    step(sim)
    panel = RightPanel(helper)
    panel.on_transport_change("SIM")
    sd = SquareDashboard(right_panel=panel)

    full = sd.layout(sim.to_dict())

    out = tmp_path / "frame.png"
    full.save(out)
    assert out.stat().st_size > 0
    assert full.size == (800, 480)
    assert full.mode == "RGBA"
