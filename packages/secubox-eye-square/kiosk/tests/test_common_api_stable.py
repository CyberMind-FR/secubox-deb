# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Catches API drift between secubox_common and its consumers."""
import inspect
import sys
from pathlib import Path

# secubox_common at /var/www/common/python/ on the image, dev checkout here.
_DEV = Path(__file__).resolve().parents[4] / "remote-ui" / "common" / "python"
if str(_DEV) not in sys.path:
    sys.path.insert(0, str(_DEV))

from secubox_common import canvas as common_canvas
from secubox_common import modules as common_modules
from secubox_common import theme as common_theme


def test_dashboard_canvas_has_documented_primitives():
    expected = {
        "paint_background", "paint_rainbow_ring", "paint_concentric_arcs",
        "paint_pod_cluster", "paint_central_button", "paint_alert_ribbon",
        "layout",
    }
    actual = {
        name for name, member in inspect.getmembers(common_canvas.DashboardCanvas)
        if not name.startswith("_") and callable(member)
    }
    missing = expected - actual
    assert not missing, f"DashboardCanvas missing methods: {missing}"


def test_six_canonical_modules():
    names = [m.name for m in common_modules.MODULES]
    assert names == ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]


def test_module_dataclass_fields():
    m = common_modules.MODULES[0]
    for field in ("name", "colour", "icon_name", "metric", "extract"):
        assert hasattr(m, field)


def test_theme_required_constants():
    for c in ("COSMOS_BLACK", "GOLD_HERMETIC", "CINNABAR",
              "MATRIX_GREEN", "CYBER_CYAN", "VOID_PURPLE",
              "TEXT_PRIMARY", "TEXT_MUTED",
              "AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"):
        assert hasattr(common_theme, c), f"theme missing {c}"


def test_square_dashboard_subclasses_canvas():
    from secubox_eye_square_kiosk.square_dashboard import SquareDashboard
    assert issubclass(SquareDashboard, common_canvas.DashboardCanvas)
