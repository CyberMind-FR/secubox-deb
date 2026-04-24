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


class TestMenuState:
    """Tests for MenuState dataclass."""

    def test_initial_dashboard_mode(self):
        """Default state is dashboard mode."""
        from menu_navigator import MenuState, MenuMode
        state = MenuState()
        assert state.mode == MenuMode.DASHBOARD
        assert state.current_menu == MenuID.ROOT
        assert state.selected_index == 0
        assert state.breadcrumb == []

    def test_enter_menu_mode(self):
        """Entering menu mode sets menu active."""
        from menu_navigator import MenuState, MenuMode
        state = MenuState()
        state.mode = MenuMode.MENU
        assert state.mode == MenuMode.MENU

    def test_breadcrumb_tracking(self):
        """Breadcrumb tracks navigation path."""
        from menu_navigator import MenuState, MenuID as NavMenuID
        state = MenuState()
        state.breadcrumb.append(MenuID.ROOT)
        state.breadcrumb.append(MenuID.SECUBOX)
        assert len(state.breadcrumb) == 2
        assert state.breadcrumb[-1] == MenuID.SECUBOX


class TestMenuNavigator:
    """Tests for MenuNavigator class."""

    def test_enter_menu_mode(self):
        """Long press center enters menu mode."""
        from menu_navigator import MenuNavigator, MenuMode
        nav = MenuNavigator()
        assert nav.state.mode == MenuMode.DASHBOARD
        nav.enter_menu()
        assert nav.state.mode == MenuMode.MENU
        assert nav.state.current_menu == MenuID.ROOT

    def test_exit_to_dashboard(self):
        """Exit returns to dashboard mode."""
        from menu_navigator import MenuNavigator, MenuMode
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.current_menu = MenuID.SECUBOX
        nav.state.breadcrumb = [MenuID.ROOT]
        nav.exit_to_dashboard()
        assert nav.state.mode == MenuMode.DASHBOARD
        assert nav.state.breadcrumb == []

    def test_navigate_to_submenu(self):
        """Selecting submenu item navigates to it."""
        from menu_navigator import MenuNavigator
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.selected_index = 0  # DEVICES
        action = nav.select_current()
        assert nav.state.current_menu == MenuID.DEVICES
        assert nav.state.breadcrumb == [MenuID.ROOT]
        assert action is None

    def test_navigate_back(self):
        """Back action returns to previous menu."""
        from menu_navigator import MenuNavigator
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.current_menu = MenuID.DEVICES
        nav.state.breadcrumb = [MenuID.ROOT]
        nav.go_back()
        assert nav.state.current_menu == MenuID.ROOT
        assert nav.state.breadcrumb == []

    def test_select_action_item(self):
        """Selecting action item returns action string."""
        from menu_navigator import MenuNavigator
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.current_menu = MenuID.DEVICES
        nav.state.selected_index = 0  # SCAN
        action = nav.select_current()
        assert action == "devices.scan"

    def test_rotate_selection_clockwise(self):
        """Swipe rotates selection clockwise."""
        from menu_navigator import MenuNavigator
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.selected_index = 2
        nav.rotate_selection(1)
        assert nav.state.selected_index == 3

    def test_rotate_selection_wraps(self):
        """Selection wraps around at boundaries."""
        from menu_navigator import MenuNavigator
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.selected_index = 5
        nav.rotate_selection(1)
        assert nav.state.selected_index == 0

    def test_get_current_items(self):
        """Get items for current menu."""
        from menu_navigator import MenuNavigator
        nav = MenuNavigator()
        nav.enter_menu()
        items = nav.get_current_items()
        assert len(items) == 6
        assert items[0].label == "DEVICES"
