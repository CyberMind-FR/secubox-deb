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


class TestMenuDefinitions:
    """Tests for static menu definitions."""

    def test_root_menu_has_six_items(self):
        """Root menu must have exactly 6 slices."""
        from menu_definitions import MENUS
        root = MENUS[MenuID.ROOT]
        assert len(root) == 6

    def test_root_menu_slice_order(self):
        """Verify correct slice order: DEVICES, SECUBOX, LOCAL, NETWORK, SECURITY, EXIT."""
        from menu_definitions import MENUS
        root = MENUS[MenuID.ROOT]
        labels = [item.label for item in root]
        assert labels == ["DEVICES", "SECUBOX", "LOCAL", "NETWORK", "SECURITY", "EXIT"]

    def test_all_submenus_have_back(self):
        """Every submenu must have a BACK item as last entry."""
        from menu_definitions import MENUS
        for menu_id, items in MENUS.items():
            if menu_id != MenuID.ROOT:
                assert items[-1].label == "< BACK"
                assert items[-1].action == "nav.back"

    def test_exit_menu_has_dashboard(self):
        """EXIT menu must have DASHBOARD as first item."""
        from menu_definitions import MENUS
        exit_menu = MENUS[MenuID.EXIT]
        assert exit_menu[0].label == "DASHBOARD"
        assert exit_menu[0].action == "nav.dashboard"
