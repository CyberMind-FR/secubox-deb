"""
Tests for menu navigation system.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from menu_definitions import MenuItem, MenuID


class TestMenuItem:
    """Tests for MenuItem dataclass."""

    def test_create_simple_item(self):
        """Create a basic menu item with action."""
        item = MenuItem(
            label="SCAN",
            icon="scan",
            action="devices.scan"
        )
        assert item.label == "SCAN"
        assert item.icon == "scan"
        assert item.action == "devices.scan"
        assert item.submenu is None
        assert item.confirm is False

    def test_create_submenu_item(self):
        """Create a menu item that opens a submenu."""
        item = MenuItem(
            label="STATUS",
            icon="status",
            submenu=MenuID.SECUBOX_STATUS
        )
        assert item.submenu == MenuID.SECUBOX_STATUS
        assert item.action is None

    def test_create_confirm_item(self):
        """Create a menu item requiring confirmation."""
        item = MenuItem(
            label="REBOOT",
            icon="reboot",
            action="system.reboot",
            confirm=True
        )
        assert item.confirm is True
