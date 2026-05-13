# packages/secubox-eye-square/kiosk/tests/test_kiosk_smoke.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Smoke test for the kiosk loop — assemble all modules and render one frame."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from PIL import Image

from secubox_eye_square_kiosk.right_panel import RightPanel
from secubox_eye_square_kiosk.ring_dashboard import RingDashboard
from secubox_eye_square_kiosk.sim import SimState, step
from secubox_eye_square_kiosk.transport_manager import TransportManager


def test_compose_full_800x480_frame(tmp_path: Path):
    """End-to-end render: dashboard + panel into a single 800x480 RGBA image."""
    tm = TransportManager(simulate=True)
    helper = MagicMock()
    sim = SimState()
    step(sim)
    rd = RingDashboard()
    rd.update_metrics(sim.to_dict())
    for _ in range(8):
        rd.advance()
    panel = RightPanel(helper)
    panel.on_transport_change("SIM")

    # Compose
    full = Image.new("RGBA", (800, 480), (0, 0, 0, 255))
    full.paste(rd.draw(), (0, 0))
    panel_img = Image.new("RGBA", (320, 480), (0, 0, 0, 255))
    panel.draw(panel_img)
    full.paste(panel_img, (480, 0))

    # Save for visual debugging
    out = tmp_path / "frame.png"
    full.save(out)
    assert out.stat().st_size > 0
    assert full.size == (800, 480)


def test_module_tap_flows_through_to_right_panel():
    """ring_dashboard.on_module_tap → panel.on_module_tap → switches to detail tab."""
    helper = MagicMock()
    rd = RingDashboard()
    panel = RightPanel(helper)
    rd.on_module_tap = panel.on_module_tap

    rd.on_module_tap("AUTH")
    assert panel.active_tab == "module_detail"
    assert panel.tabs["module_detail"].module_name == "AUTH"
