"""
Tests for radial menu renderer.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from radial_renderer import RadialRenderer, SLICE_COLORS


class TestRadialRenderer:
    """Tests for RadialRenderer class."""

    def test_init_creates_canvas(self):
        """Renderer initializes with correct dimensions."""
        renderer = RadialRenderer()
        assert renderer.width == 480
        assert renderer.height == 480
        # Canvas is created during render(), not __init__
        assert renderer.canvas is None

    def test_slice_colors_defined(self):
        """All 6 slices have colors defined."""
        assert len(SLICE_COLORS) == 6
        for color in SLICE_COLORS:
            assert color.startswith("#")

    def test_calculate_slice_angles(self):
        """Calculate correct start/end angles for each slice."""
        renderer = RadialRenderer()
        angles = renderer.get_slice_angles(0)
        assert angles['start'] == -30
        assert angles['end'] == 30
        angles = renderer.get_slice_angles(3)
        assert angles['start'] == 150
        assert angles['end'] == 210

    def test_render_creates_image(self):
        """Render produces an image."""
        from menu_navigator import MenuState, MenuMode
        from menu_definitions import MenuID

        renderer = RadialRenderer()
        state = MenuState(
            mode=MenuMode.MENU,
            current_menu=MenuID.ROOT,
            selected_index=0
        )
        image = renderer.render(state)
        assert image is not None
        assert image.size == (480, 480)
