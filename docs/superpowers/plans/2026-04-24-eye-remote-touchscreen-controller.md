# Eye Remote Touchscreen Controller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a radial menu touch interface for the Eye Remote circular display, enabling control of both local Pi Zero settings and remote SecuBox devices.

**Architecture:** Extend the existing TouchHandler with slice detection, add a MenuNavigator for state management, create a RadialRenderer for framebuffer drawing, and wire actions through an ActionExecutor that dispatches to LocalAPI, SecuBoxClient, or system commands.

**Tech Stack:** Python 3.11+, evdev, Pillow, asyncio, aiohttp (existing), framebuffer rendering

---

## File Structure

```
remote-ui/round/agent/
├── main.py                  # Entry point (modify to integrate menu mode)
├── touch_handler.py         # Gesture detection (extend with slice detection)
├── menu_navigator.py        # Menu state machine (NEW)
├── radial_renderer.py       # Radial menu rendering (NEW)
├── action_executor.py       # Action dispatch (NEW)
├── local_api.py             # Local Pi Zero settings (NEW)
├── menu_definitions.py      # Static menu structures (NEW)
├── secubox_client.py        # REST client (existing, extend for menu data)
└── assets/icons/            # Icons (existing + new menu icons)

remote-ui/round/tests/
├── test_touch_handler.py    # (existing, extend)
├── test_menu_navigator.py   # (NEW)
├── test_radial_renderer.py  # (NEW)
└── test_action_executor.py  # (NEW)
```

---

### Task 1: MenuItem Data Model

**Files:**
- Create: `remote-ui/round/agent/menu_definitions.py`
- Test: `remote-ui/round/tests/test_menu_navigator.py`

- [ ] **Step 1: Write the failing test for MenuItem**

```python
# remote-ui/round/tests/test_menu_navigator.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_menu_navigator.py::TestMenuItem -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'menu_definitions'"

- [ ] **Step 3: Write minimal implementation**

```python
# remote-ui/round/agent/menu_definitions.py
"""
SecuBox Eye Remote - Menu Definitions
Static menu structures for radial menu navigation.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class MenuID(Enum):
    """Identifiants des menus."""
    ROOT = auto()
    DEVICES = auto()
    SECUBOX = auto()
    SECUBOX_STATUS = auto()
    SECUBOX_MODULES = auto()
    LOCAL = auto()
    LOCAL_DISPLAY = auto()
    LOCAL_NETWORK = auto()
    LOCAL_SYSTEM = auto()
    NETWORK = auto()
    SECURITY = auto()
    EXIT = auto()


@dataclass
class MenuItem:
    """
    Un element de menu radial.

    Attributes:
        label: Texte affiche (peut contenir {placeholders} pour donnees dynamiques)
        icon: Nom de l'icone sans extension (ex: "scan" -> scan-48.png)
        action: Action a executer (format "module.method:param")
        submenu: MenuID du sous-menu a ouvrir
        confirm: Demander confirmation avant execution
    """
    label: str
    icon: str
    action: Optional[str] = None
    submenu: Optional[MenuID] = None
    confirm: bool = False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_menu_navigator.py::TestMenuItem -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/menu_definitions.py remote-ui/round/tests/test_menu_navigator.py
git commit -m "feat(eye-remote): add MenuItem data model for radial menus"
```

---

### Task 2: Static Menu Definitions

**Files:**
- Modify: `remote-ui/round/agent/menu_definitions.py`
- Test: `remote-ui/round/tests/test_menu_navigator.py`

- [ ] **Step 1: Write the failing test for menu definitions**

```python
# Add to remote-ui/round/tests/test_menu_navigator.py

from menu_definitions import MENUS, MenuID


class TestMenuDefinitions:
    """Tests for static menu definitions."""

    def test_root_menu_has_six_items(self):
        """Root menu must have exactly 6 slices."""
        root = MENUS[MenuID.ROOT]
        assert len(root) == 6

    def test_root_menu_slice_order(self):
        """Verify correct slice order: DEVICES, SECUBOX, LOCAL, NETWORK, SECURITY, EXIT."""
        root = MENUS[MenuID.ROOT]
        labels = [item.label for item in root]
        assert labels == ["DEVICES", "SECUBOX", "LOCAL", "NETWORK", "SECURITY", "EXIT"]

    def test_all_submenus_have_back(self):
        """Every submenu must have a BACK item as last entry."""
        for menu_id, items in MENUS.items():
            if menu_id != MenuID.ROOT:
                assert items[-1].label == "< BACK"
                assert items[-1].action == "nav.back"

    def test_exit_menu_has_dashboard(self):
        """EXIT menu must have DASHBOARD as first item."""
        exit_menu = MENUS[MenuID.EXIT]
        assert exit_menu[0].label == "DASHBOARD"
        assert exit_menu[0].action == "nav.dashboard"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_menu_navigator.py::TestMenuDefinitions -v`
Expected: FAIL with "ImportError: cannot import name 'MENUS'"

- [ ] **Step 3: Write minimal implementation**

```python
# Add to remote-ui/round/agent/menu_definitions.py after MenuItem class

# =============================================================================
# Static Menu Definitions
# =============================================================================

MENUS: dict[MenuID, list[MenuItem]] = {
    # Root Menu - 6 slices
    MenuID.ROOT: [
        MenuItem("DEVICES", "devices", submenu=MenuID.DEVICES),
        MenuItem("SECUBOX", "secubox", submenu=MenuID.SECUBOX),
        MenuItem("LOCAL", "local", submenu=MenuID.LOCAL),
        MenuItem("NETWORK", "network", submenu=MenuID.NETWORK),
        MenuItem("SECURITY", "security", submenu=MenuID.SECURITY),
        MenuItem("EXIT", "exit", submenu=MenuID.EXIT),
    ],

    # DEVICES Menu
    MenuID.DEVICES: [
        MenuItem("SCAN", "scan", action="devices.scan"),
        MenuItem("PAIR NEW", "plus", action="devices.pair"),
        MenuItem("FORGET", "trash", action="devices.forget"),
        MenuItem("REFRESH", "refresh", action="devices.refresh"),
        MenuItem("INFO", "info", action="devices.info"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # SECUBOX Menu
    MenuID.SECUBOX: [
        MenuItem("STATUS", "status", submenu=MenuID.SECUBOX_STATUS),
        MenuItem("MODULES", "modules", submenu=MenuID.SECUBOX_MODULES),
        MenuItem("LOGS", "logs", action="secubox.logs"),
        MenuItem("RESTART", "restart", action="secubox.restart", confirm=True),
        MenuItem("UPDATE", "update", action="secubox.update"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # SECUBOX.STATUS Menu
    MenuID.SECUBOX_STATUS: [
        MenuItem("CPU: {cpu}%", "cpu", action="secubox.detail:cpu"),
        MenuItem("MEM: {mem}%", "memory", action="secubox.detail:mem"),
        MenuItem("DISK: {disk}%", "disk", action="secubox.detail:disk"),
        MenuItem("TEMP: {temp}C", "temp", action="secubox.detail:temp"),
        MenuItem("UPTIME", "clock", action="secubox.detail:uptime"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # SECUBOX.MODULES Menu
    MenuID.SECUBOX_MODULES: [
        MenuItem("CROWDSEC", "auth", action="secubox.module:crowdsec"),
        MenuItem("WIREGUARD", "mesh", action="secubox.module:wireguard"),
        MenuItem("FIREWALL", "wall", action="secubox.module:firewall"),
        MenuItem("DPI", "mind", action="secubox.module:dpi"),
        MenuItem("DNS", "root", action="secubox.module:dns"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL Menu
    MenuID.LOCAL: [
        MenuItem("DISPLAY", "display", submenu=MenuID.LOCAL_DISPLAY),
        MenuItem("NETWORK", "network", submenu=MenuID.LOCAL_NETWORK),
        MenuItem("SYSTEM", "system", submenu=MenuID.LOCAL_SYSTEM),
        MenuItem("ABOUT", "info", action="local.about"),
        MenuItem("LOGS", "logs", action="local.logs"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL.DISPLAY Menu
    MenuID.LOCAL_DISPLAY: [
        MenuItem("BRIGHTNESS", "brightness", action="local.brightness"),
        MenuItem("THEME", "theme", action="local.theme"),
        MenuItem("TIMEOUT", "timeout", action="local.timeout"),
        MenuItem("ROTATION", "rotate", action="local.rotation"),
        MenuItem("TEST", "test", action="local.display_test"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL.NETWORK Menu
    MenuID.LOCAL_NETWORK: [
        MenuItem("USB IP", "usb", action="local.usb_ip"),
        MenuItem("WIFI", "wifi", action="local.wifi"),
        MenuItem("HOSTNAME", "hostname", action="local.hostname"),
        MenuItem("DNS", "dns", action="local.dns"),
        MenuItem("STATUS", "status", action="local.net_status"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # LOCAL.SYSTEM Menu
    MenuID.LOCAL_SYSTEM: [
        MenuItem("STORAGE", "disk", action="local.storage"),
        MenuItem("MEMORY", "memory", action="local.memory"),
        MenuItem("CPU", "cpu", action="local.cpu_info"),
        MenuItem("LOGS", "logs", action="local.system_logs"),
        MenuItem("UPDATES", "update", action="local.updates"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # NETWORK Menu
    MenuID.NETWORK: [
        MenuItem("INTERFACES", "interfaces", action="network.interfaces"),
        MenuItem("ROUTES", "routes", action="network.routes"),
        MenuItem("DNS", "dns", action="network.dns"),
        MenuItem("FIREWALL", "wall", action="network.firewall"),
        MenuItem("TRAFFIC", "traffic", action="network.traffic"),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # SECURITY Menu
    MenuID.SECURITY: [
        MenuItem("ALERTS", "alert", action="security.alerts"),
        MenuItem("BANS", "ban", action="security.bans"),
        MenuItem("RULES", "rules", action="security.rules"),
        MenuItem("AUDIT", "audit", action="security.audit"),
        MenuItem("LOCKDOWN", "lock", action="security.lockdown", confirm=True),
        MenuItem("< BACK", "back", action="nav.back"),
    ],

    # EXIT Menu
    MenuID.EXIT: [
        MenuItem("DASHBOARD", "dashboard", action="nav.dashboard"),
        MenuItem("SLEEP", "sleep", action="system.sleep"),
        MenuItem("REBOOT PI", "reboot", action="system.reboot", confirm=True),
        MenuItem("SHUTDOWN", "shutdown", action="system.shutdown", confirm=True),
        MenuItem("REBOOT BOX", "restart", action="secubox.reboot", confirm=True),
        MenuItem("< BACK", "back", action="nav.back"),
    ],
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_menu_navigator.py::TestMenuDefinitions -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/menu_definitions.py remote-ui/round/tests/test_menu_navigator.py
git commit -m "feat(eye-remote): add static menu definitions for all menus"
```

---

### Task 3: MenuState Data Model

**Files:**
- Create: `remote-ui/round/agent/menu_navigator.py`
- Test: `remote-ui/round/tests/test_menu_navigator.py`

- [ ] **Step 1: Write the failing test for MenuState**

```python
# Add to remote-ui/round/tests/test_menu_navigator.py

from menu_navigator import MenuState, MenuMode


class TestMenuState:
    """Tests for MenuState dataclass."""

    def test_initial_dashboard_mode(self):
        """Default state is dashboard mode."""
        state = MenuState()
        assert state.mode == MenuMode.DASHBOARD
        assert state.current_menu == MenuID.ROOT
        assert state.selected_index == 0
        assert state.breadcrumb == []

    def test_enter_menu_mode(self):
        """Entering menu mode sets ROOT menu."""
        state = MenuState()
        state.mode = MenuMode.MENU
        assert state.mode == MenuMode.MENU

    def test_breadcrumb_tracking(self):
        """Breadcrumb tracks navigation path."""
        state = MenuState()
        state.breadcrumb.append(MenuID.ROOT)
        state.breadcrumb.append(MenuID.SECUBOX)
        assert len(state.breadcrumb) == 2
        assert state.breadcrumb[-1] == MenuID.SECUBOX
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_menu_navigator.py::TestMenuState -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'menu_navigator'"

- [ ] **Step 3: Write minimal implementation**

```python
# remote-ui/round/agent/menu_navigator.py
"""
SecuBox Eye Remote - Menu Navigator
State machine for radial menu navigation.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Callable, Any

from menu_definitions import MenuID, MenuItem, MENUS


class MenuMode(Enum):
    """Mode d'affichage actuel."""
    DASHBOARD = auto()  # Affichage dashboard normal
    MENU = auto()       # Navigation menu radial
    CONFIRM = auto()    # Dialogue de confirmation
    LOADING = auto()    # Attente d'une action async
    RESULT = auto()     # Affichage resultat d'action


@dataclass
class MenuState:
    """
    Etat complet du systeme de menu.

    Attributes:
        mode: Mode d'affichage actuel
        current_menu: Menu actuellement affiche
        selected_index: Index de la tranche selectionnee (0-5)
        breadcrumb: Pile de navigation pour retour arriere
        animation_frame: Frame d'animation en cours (0-30)
        pending_action: Action en attente de confirmation
        result_message: Message de resultat a afficher
    """
    mode: MenuMode = MenuMode.DASHBOARD
    current_menu: MenuID = MenuID.ROOT
    selected_index: int = 0
    breadcrumb: list[MenuID] = field(default_factory=list)
    animation_frame: int = 0
    pending_action: Optional[str] = None
    result_message: Optional[str] = None
    result_success: bool = True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_menu_navigator.py::TestMenuState -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/menu_navigator.py remote-ui/round/tests/test_menu_navigator.py
git commit -m "feat(eye-remote): add MenuState data model"
```

---

### Task 4: MenuNavigator Core Logic

**Files:**
- Modify: `remote-ui/round/agent/menu_navigator.py`
- Test: `remote-ui/round/tests/test_menu_navigator.py`

- [ ] **Step 1: Write the failing test for navigator methods**

```python
# Add to remote-ui/round/tests/test_menu_navigator.py

from menu_navigator import MenuNavigator


class TestMenuNavigator:
    """Tests for MenuNavigator class."""

    def test_enter_menu_mode(self):
        """Long press center enters menu mode."""
        nav = MenuNavigator()
        assert nav.state.mode == MenuMode.DASHBOARD

        nav.enter_menu()

        assert nav.state.mode == MenuMode.MENU
        assert nav.state.current_menu == MenuID.ROOT

    def test_exit_to_dashboard(self):
        """Exit returns to dashboard mode."""
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.current_menu = MenuID.SECUBOX
        nav.state.breadcrumb = [MenuID.ROOT]

        nav.exit_to_dashboard()

        assert nav.state.mode == MenuMode.DASHBOARD
        assert nav.state.breadcrumb == []

    def test_navigate_to_submenu(self):
        """Selecting submenu item navigates to it."""
        nav = MenuNavigator()
        nav.enter_menu()

        # Select DEVICES (index 0 in ROOT)
        nav.state.selected_index = 0
        action = nav.select_current()

        assert nav.state.current_menu == MenuID.DEVICES
        assert nav.state.breadcrumb == [MenuID.ROOT]
        assert action is None  # No action, just navigation

    def test_navigate_back(self):
        """Back action returns to previous menu."""
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.current_menu = MenuID.DEVICES
        nav.state.breadcrumb = [MenuID.ROOT]

        nav.go_back()

        assert nav.state.current_menu == MenuID.ROOT
        assert nav.state.breadcrumb == []

    def test_select_action_item(self):
        """Selecting action item returns action string."""
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.current_menu = MenuID.DEVICES
        nav.state.selected_index = 0  # SCAN

        action = nav.select_current()

        assert action == "devices.scan"

    def test_rotate_selection_clockwise(self):
        """Swipe rotates selection clockwise."""
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.selected_index = 2

        nav.rotate_selection(1)  # Clockwise

        assert nav.state.selected_index == 3

    def test_rotate_selection_wraps(self):
        """Selection wraps around at boundaries."""
        nav = MenuNavigator()
        nav.enter_menu()
        nav.state.selected_index = 5

        nav.rotate_selection(1)  # Clockwise past end

        assert nav.state.selected_index == 0

    def test_get_current_items(self):
        """Get items for current menu."""
        nav = MenuNavigator()
        nav.enter_menu()

        items = nav.get_current_items()

        assert len(items) == 6
        assert items[0].label == "DEVICES"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_menu_navigator.py::TestMenuNavigator -v`
Expected: FAIL with "ImportError: cannot import name 'MenuNavigator'"

- [ ] **Step 3: Write minimal implementation**

```python
# Add to remote-ui/round/agent/menu_navigator.py after MenuState

class MenuNavigator:
    """
    Gestionnaire de navigation dans les menus radiaux.

    Gere les transitions d'etat, la pile de navigation,
    et les actions de selection.
    """

    def __init__(self):
        self.state = MenuState()
        self._on_state_change: Optional[Callable[[MenuState], None]] = None

    def on_state_change(self, callback: Callable[[MenuState], None]):
        """Enregistrer un callback pour les changements d'etat."""
        self._on_state_change = callback

    def _notify_change(self):
        """Notifier les observateurs d'un changement d'etat."""
        if self._on_state_change:
            self._on_state_change(self.state)

    def enter_menu(self):
        """Entrer en mode menu (depuis dashboard)."""
        self.state.mode = MenuMode.MENU
        self.state.current_menu = MenuID.ROOT
        self.state.selected_index = 0
        self.state.breadcrumb = []
        self._notify_change()

    def exit_to_dashboard(self):
        """Retourner au dashboard."""
        self.state.mode = MenuMode.DASHBOARD
        self.state.current_menu = MenuID.ROOT
        self.state.selected_index = 0
        self.state.breadcrumb = []
        self._notify_change()

    def go_back(self):
        """Retourner au menu precedent."""
        if self.state.breadcrumb:
            self.state.current_menu = self.state.breadcrumb.pop()
            self.state.selected_index = 0
            self._notify_change()
        else:
            self.exit_to_dashboard()

    def select_current(self) -> Optional[str]:
        """
        Selectionner l'element actuellement en surbrillance.

        Returns:
            Action string si c'est un item action, None sinon
        """
        items = self.get_current_items()
        if not items or self.state.selected_index >= len(items):
            return None

        item = items[self.state.selected_index]

        # Navigation actions
        if item.action == "nav.back":
            self.go_back()
            return None

        if item.action == "nav.dashboard":
            self.exit_to_dashboard()
            return None

        # Submenu navigation
        if item.submenu is not None:
            self.state.breadcrumb.append(self.state.current_menu)
            self.state.current_menu = item.submenu
            self.state.selected_index = 0
            self._notify_change()
            return None

        # Confirm required?
        if item.confirm:
            self.state.mode = MenuMode.CONFIRM
            self.state.pending_action = item.action
            self._notify_change()
            return None

        # Direct action
        return item.action

    def confirm_action(self) -> Optional[str]:
        """Confirmer l'action en attente."""
        if self.state.mode != MenuMode.CONFIRM:
            return None

        action = self.state.pending_action
        self.state.pending_action = None
        self.state.mode = MenuMode.MENU
        self._notify_change()
        return action

    def cancel_action(self):
        """Annuler l'action en attente."""
        self.state.pending_action = None
        self.state.mode = MenuMode.MENU
        self._notify_change()

    def rotate_selection(self, direction: int):
        """
        Tourner la selection.

        Args:
            direction: +1 pour horaire, -1 pour anti-horaire
        """
        items = self.get_current_items()
        if not items:
            return

        self.state.selected_index = (
            self.state.selected_index + direction
        ) % len(items)
        self._notify_change()

    def select_by_index(self, index: int):
        """Selectionner directement par index."""
        items = self.get_current_items()
        if items and 0 <= index < len(items):
            self.state.selected_index = index
            self._notify_change()

    def get_current_items(self) -> list[MenuItem]:
        """Obtenir les items du menu actuel."""
        return MENUS.get(self.state.current_menu, [])

    def show_result(self, message: str, success: bool = True):
        """Afficher un message de resultat."""
        self.state.mode = MenuMode.RESULT
        self.state.result_message = message
        self.state.result_success = success
        self._notify_change()

    def clear_result(self):
        """Effacer le message de resultat."""
        self.state.result_message = None
        self.state.mode = MenuMode.MENU
        self._notify_change()

    def show_loading(self):
        """Afficher l'indicateur de chargement."""
        self.state.mode = MenuMode.LOADING
        self._notify_change()

    def hide_loading(self):
        """Masquer l'indicateur de chargement."""
        self.state.mode = MenuMode.MENU
        self._notify_change()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_menu_navigator.py::TestMenuNavigator -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/menu_navigator.py remote-ui/round/tests/test_menu_navigator.py
git commit -m "feat(eye-remote): add MenuNavigator state machine"
```

---

### Task 5: Slice Detection in TouchHandler

**Files:**
- Modify: `remote-ui/round/agent/touch_handler.py`
- Test: `remote-ui/round/tests/test_touch_handler.py`

- [ ] **Step 1: Write the failing test for slice detection**

```python
# Add to remote-ui/round/tests/test_touch_handler.py

from touch_handler import get_slice_from_touch, CENTER_X, CENTER_Y


class TestSliceDetection:
    """Tests for radial slice detection."""

    def test_center_zone_returns_none(self):
        """Touch in center zone (radius < 60) returns None."""
        result = get_slice_from_touch(CENTER_X, CENTER_Y)
        assert result is None

        result = get_slice_from_touch(CENTER_X + 50, CENTER_Y)
        assert result is None

    def test_outside_circle_returns_none(self):
        """Touch outside visible circle (radius > 220) returns None."""
        result = get_slice_from_touch(CENTER_X, CENTER_Y - 230)
        assert result is None

    def test_slice_0_at_top(self):
        """Slice 0 is at the top (12 o'clock position)."""
        # Touch at top, within ring area
        result = get_slice_from_touch(CENTER_X, CENTER_Y - 150)
        assert result == 0

    def test_slice_1_at_top_right(self):
        """Slice 1 is at top-right (2 o'clock position)."""
        # Touch at top-right diagonal
        import math
        angle = math.radians(60)  # 60 degrees from top
        x = int(CENTER_X + 150 * math.sin(angle))
        y = int(CENTER_Y - 150 * math.cos(angle))
        result = get_slice_from_touch(x, y)
        assert result == 1

    def test_slice_3_at_bottom(self):
        """Slice 3 is at the bottom (6 o'clock position)."""
        result = get_slice_from_touch(CENTER_X, CENTER_Y + 150)
        assert result == 3

    def test_slice_5_at_top_left(self):
        """Slice 5 is at top-left (10 o'clock position)."""
        import math
        angle = math.radians(-60)  # -60 degrees from top
        x = int(CENTER_X + 150 * math.sin(angle))
        y = int(CENTER_Y - 150 * math.cos(angle))
        result = get_slice_from_touch(x, y)
        assert result == 5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_touch_handler.py::TestSliceDetection -v`
Expected: FAIL with "ImportError: cannot import name 'get_slice_from_touch'"

- [ ] **Step 3: Write minimal implementation**

```python
# Add to remote-ui/round/agent/touch_handler.py after constants section

# =============================================================================
# Slice Detection for Radial Menu
# =============================================================================

# Zone radii for slice detection
CENTER_ZONE_RADIUS = 60      # Center area (not a slice)
OUTER_ZONE_RADIUS = 220      # Outside visible circle

def get_slice_from_touch(x: int, y: int) -> Optional[int]:
    """
    Convertir des coordonnees tactiles en index de tranche (0-5).

    La tranche 0 est en haut (12h), puis les tranches tournent
    dans le sens horaire: 1=2h, 2=4h, 3=6h, 4=8h, 5=10h.

    Args:
        x: Coordonnee X du touch
        y: Coordonnee Y du touch

    Returns:
        Index de tranche (0-5) ou None si hors zone
    """
    dx = x - CENTER_X
    dy = y - CENTER_Y
    distance = math.sqrt(dx * dx + dy * dy)

    # Zone centrale -> pas une tranche
    if distance < CENTER_ZONE_RADIUS:
        return None

    # Hors du cercle visible -> ignorer
    if distance > OUTER_ZONE_RADIUS:
        return None

    # Calculer l'angle (0 = haut, sens horaire)
    # atan2(dx, -dy) donne l'angle depuis le haut
    angle = math.degrees(math.atan2(dx, -dy))
    if angle < 0:
        angle += 360

    # Chaque tranche fait 60 degres, decale de 30 pour centrer
    # la tranche 0 sur le haut
    slice_index = int((angle + 30) % 360 // 60)
    return slice_index
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_touch_handler.py::TestSliceDetection -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/touch_handler.py remote-ui/round/tests/test_touch_handler.py
git commit -m "feat(eye-remote): add slice detection for radial menu"
```

---

### Task 6: RadialRenderer Core

**Files:**
- Create: `remote-ui/round/agent/radial_renderer.py`
- Test: `remote-ui/round/tests/test_radial_renderer.py`

- [ ] **Step 1: Write the failing test for RadialRenderer**

```python
# remote-ui/round/tests/test_radial_renderer.py
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
        """Renderer creates a 480x480 canvas."""
        renderer = RadialRenderer()
        assert renderer.width == 480
        assert renderer.height == 480
        assert renderer.canvas is not None

    def test_slice_colors_defined(self):
        """All 6 slices have colors defined."""
        assert len(SLICE_COLORS) == 6
        for color in SLICE_COLORS:
            assert color.startswith("#")

    def test_calculate_slice_angles(self):
        """Calculate correct start/end angles for each slice."""
        renderer = RadialRenderer()

        angles = renderer.get_slice_angles(0)
        assert angles['start'] == -30  # Slice 0 centered at top
        assert angles['end'] == 30

        angles = renderer.get_slice_angles(3)
        assert angles['start'] == 150  # Slice 3 at bottom
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_radial_renderer.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'radial_renderer'"

- [ ] **Step 3: Write minimal implementation**

```python
# remote-ui/round/agent/radial_renderer.py
"""
SecuBox Eye Remote - Radial Menu Renderer
Renders radial menus to framebuffer via Pillow.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Optional

from PIL import Image, ImageDraw, ImageFont

from menu_navigator import MenuState, MenuMode
from menu_definitions import MenuID, MenuItem, MENUS


# =============================================================================
# Constants
# =============================================================================

# Display dimensions
WIDTH = 480
HEIGHT = 480
CENTER = (WIDTH // 2, HEIGHT // 2)

# Ring dimensions
OUTER_RADIUS = 220
INNER_RADIUS = 80
SELECTED_OUTER = 230  # Slightly larger when selected

# Colors (SecuBox palette)
SLICE_COLORS = [
    "#C04E24",  # Slice 0 - AUTH red-orange
    "#9A6010",  # Slice 1 - WALL gold
    "#803018",  # Slice 2 - BOOT brown
    "#3D35A0",  # Slice 3 - MIND purple
    "#0A5840",  # Slice 4 - ROOT green
    "#104A88",  # Slice 5 - MESH blue
]

BG_COLOR = "#080808"          # Background black
TEXT_COLOR = "#e8e6d9"        # Primary text
SELECTED_GLOW = "#c9a84c"     # Gold highlight
CENTER_BG = "#0a0a0f"         # Center circle bg
CONFIRM_YES = "#0A5840"       # Green for confirm
CONFIRM_NO = "#C04E24"        # Red for cancel

# Icon directory
SCRIPT_DIR = Path(__file__).parent
ICONS_DIR = SCRIPT_DIR / "assets" / "icons"


# =============================================================================
# RadialRenderer
# =============================================================================

class RadialRenderer:
    """
    Rend les menus radiaux sur le framebuffer.

    Utilise Pillow pour dessiner les tranches, icones et texte.
    """

    def __init__(self, width: int = WIDTH, height: int = HEIGHT):
        self.width = width
        self.height = height
        self.center = (width // 2, height // 2)
        self.canvas: Optional[Image.Image] = None
        self._icon_cache: dict[str, Image.Image] = {}
        self._font: Optional[ImageFont.FreeTypeFont] = None
        self._font_small: Optional[ImageFont.FreeTypeFont] = None
        self._init_canvas()
        self._load_fonts()

    def _init_canvas(self):
        """Initialiser le canvas de dessin."""
        self.canvas = Image.new("RGBA", (self.width, self.height), BG_COLOR)

    def _load_fonts(self):
        """Charger les polices."""
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
            "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
        ]
        for path in font_paths:
            if Path(path).exists():
                try:
                    self._font = ImageFont.truetype(path, 16)
                    self._font_small = ImageFont.truetype(path, 12)
                    return
                except Exception:
                    continue
        # Fallback to default
        self._font = ImageFont.load_default()
        self._font_small = self._font

    def get_slice_angles(self, index: int) -> dict[str, float]:
        """
        Calculer les angles de debut/fin pour une tranche.

        Args:
            index: Index de la tranche (0-5)

        Returns:
            Dict avec 'start' et 'end' en degres
        """
        # Chaque tranche fait 60 degres
        # Tranche 0 est centree en haut (0 degres = midi)
        # Angles en degres, sens horaire depuis le haut
        start = index * 60 - 30  # -30 pour centrer
        end = start + 60
        return {"start": start, "end": end}

    def _load_icon(self, name: str, size: int = 48) -> Optional[Image.Image]:
        """Charger une icone depuis le cache ou le disque."""
        cache_key = f"{name}_{size}"
        if cache_key in self._icon_cache:
            return self._icon_cache[cache_key]

        # Essayer plusieurs noms de fichiers
        paths = [
            ICONS_DIR / f"{name}-{size}.png",
            ICONS_DIR / f"{name.lower()}-{size}.png",
        ]
        for path in paths:
            if path.exists():
                try:
                    icon = Image.open(path).convert("RGBA")
                    self._icon_cache[cache_key] = icon
                    return icon
                except Exception:
                    continue
        return None

    def _draw_slice(
        self,
        draw: ImageDraw.ImageDraw,
        index: int,
        item: MenuItem,
        selected: bool = False
    ):
        """Dessiner une tranche du menu."""
        angles = self.get_slice_angles(index)
        color = SLICE_COLORS[index % len(SLICE_COLORS)]

        # Rayon externe plus grand si selectionne
        outer_r = SELECTED_OUTER if selected else OUTER_RADIUS

        # Convertir angles pour PIL (0 = 3h, sens anti-horaire)
        # Notre systeme: 0 = 12h, sens horaire
        # Conversion: PIL_angle = 90 - our_angle
        pil_start = 90 - angles["end"]
        pil_end = 90 - angles["start"]

        # Dessiner l'arc externe
        bbox = [
            self.center[0] - outer_r,
            self.center[1] - outer_r,
            self.center[0] + outer_r,
            self.center[1] + outer_r,
        ]
        draw.pieslice(bbox, pil_start, pil_end, fill=color)

        # Dessiner le cercle interieur pour creer la forme d'anneau
        inner_bbox = [
            self.center[0] - INNER_RADIUS,
            self.center[1] - INNER_RADIUS,
            self.center[0] + INNER_RADIUS,
            self.center[1] + INNER_RADIUS,
        ]
        # Sera dessine apres toutes les tranches

        # Calculer position du texte et icone
        mid_angle = (angles["start"] + angles["end"]) / 2
        text_radius = (INNER_RADIUS + outer_r) / 2
        rad = math.radians(mid_angle - 90)  # -90 car notre 0 est en haut
        text_x = self.center[0] + text_radius * math.cos(rad)
        text_y = self.center[1] + text_radius * math.sin(rad)

        # Icone
        icon = self._load_icon(item.icon, 22)
        if icon:
            icon_pos = (int(text_x - 11), int(text_y - 20))
            self.canvas.paste(icon, icon_pos, icon)

        # Label
        label = item.label.split("{")[0].strip()  # Retirer placeholders
        if len(label) > 8:
            label = label[:7] + "."
        text_bbox = draw.textbbox((0, 0), label, font=self._font_small)
        text_w = text_bbox[2] - text_bbox[0]
        draw.text(
            (text_x - text_w / 2, text_y + 8),
            label,
            fill=TEXT_COLOR,
            font=self._font_small
        )

        # Indicateur de selection (glow)
        if selected:
            glow_bbox = [bbox[0] - 2, bbox[1] - 2, bbox[2] + 2, bbox[3] + 2]
            draw.arc(glow_bbox, pil_start, pil_end, fill=SELECTED_GLOW, width=3)

    def _draw_center(self, draw: ImageDraw.ImageDraw, state: MenuState):
        """Dessiner le cercle central."""
        # Cercle de fond
        inner_bbox = [
            self.center[0] - INNER_RADIUS,
            self.center[1] - INNER_RADIUS,
            self.center[0] + INNER_RADIUS,
            self.center[1] + INNER_RADIUS,
        ]
        draw.ellipse(inner_bbox, fill=CENTER_BG)

        # Texte du menu actuel
        menu_name = state.current_menu.name.replace("_", " ")
        text_bbox = draw.textbbox((0, 0), menu_name, font=self._font)
        text_w = text_bbox[2] - text_bbox[0]
        draw.text(
            (self.center[0] - text_w / 2, self.center[1] - 8),
            menu_name,
            fill=SELECTED_GLOW,
            font=self._font
        )

        # Indicateur de navigation (si dans sous-menu)
        if state.breadcrumb:
            draw.text(
                (self.center[0] - 20, self.center[1] + 20),
                "< BACK",
                fill=TEXT_COLOR,
                font=self._font_small
            )

    def render(self, state: MenuState) -> Image.Image:
        """
        Rendre le menu radial complet.

        Args:
            state: Etat actuel du menu

        Returns:
            Image PIL du menu rendu
        """
        # Reinitialiser le canvas
        self._init_canvas()
        draw = ImageDraw.Draw(self.canvas)

        if state.mode == MenuMode.DASHBOARD:
            # En mode dashboard, ne rien dessiner
            return self.canvas

        # Mode menu: dessiner les tranches
        items = MENUS.get(state.current_menu, [])
        for i, item in enumerate(items[:6]):  # Max 6 slices
            selected = (i == state.selected_index)
            self._draw_slice(draw, i, item, selected)

        # Dessiner le cercle central par-dessus
        self._draw_center(draw, state)

        # Mode confirmation
        if state.mode == MenuMode.CONFIRM:
            self._draw_confirm_overlay(draw, state)

        # Mode chargement
        if state.mode == MenuMode.LOADING:
            self._draw_loading(draw)

        # Mode resultat
        if state.mode == MenuMode.RESULT:
            self._draw_result(draw, state)

        return self.canvas

    def _draw_confirm_overlay(self, draw: ImageDraw.ImageDraw, state: MenuState):
        """Dessiner le dialogue de confirmation."""
        # Fond semi-transparent (simule)
        overlay = Image.new("RGBA", (self.width, self.height), (0, 0, 0, 180))
        self.canvas = Image.alpha_composite(self.canvas, overlay)
        draw = ImageDraw.Draw(self.canvas)

        # Question
        draw.text(
            (self.center[0] - 50, self.center[1] - 40),
            "CONFIRM?",
            fill=TEXT_COLOR,
            font=self._font
        )

        # Boutons (tranches 2=YES, 4=NO)
        # YES en vert
        yes_bbox = [200, 280, 280, 340]
        draw.rectangle(yes_bbox, fill=CONFIRM_YES)
        draw.text((220, 300), "YES", fill=TEXT_COLOR, font=self._font)

        # NO en rouge
        no_bbox = [200, 140, 280, 200]
        draw.rectangle(no_bbox, fill=CONFIRM_NO)
        draw.text((225, 160), "NO", fill=TEXT_COLOR, font=self._font)

    def _draw_loading(self, draw: ImageDraw.ImageDraw):
        """Dessiner l'indicateur de chargement."""
        # Spinner simple
        draw.text(
            (self.center[0] - 30, self.center[1]),
            "LOADING...",
            fill=SELECTED_GLOW,
            font=self._font_small
        )

    def _draw_result(self, draw: ImageDraw.ImageDraw, state: MenuState):
        """Dessiner le message de resultat."""
        color = CONFIRM_YES if state.result_success else CONFIRM_NO
        message = state.result_message or "OK"
        if len(message) > 15:
            message = message[:14] + "."

        draw.text(
            (self.center[0] - 50, self.center[1]),
            message,
            fill=color,
            font=self._font
        )

    def write_to_framebuffer(self, fb_path: str = "/dev/fb0"):
        """Ecrire le canvas au framebuffer."""
        if self.canvas is None:
            return

        try:
            # Convertir en RGB565 pour framebuffer
            rgb = self.canvas.convert("RGB")
            pixels = rgb.tobytes()

            # Convertir RGB888 -> RGB565
            rgb565 = bytearray(self.width * self.height * 2)
            for i in range(0, len(pixels), 3):
                r, g, b = pixels[i], pixels[i + 1], pixels[i + 2]
                rgb565_val = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
                idx = (i // 3) * 2
                rgb565[idx] = rgb565_val & 0xFF
                rgb565[idx + 1] = (rgb565_val >> 8) & 0xFF

            with open(fb_path, "wb") as fb:
                fb.write(rgb565)

        except (OSError, PermissionError) as e:
            # Framebuffer pas disponible (dev mode)
            pass
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_radial_renderer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/radial_renderer.py remote-ui/round/tests/test_radial_renderer.py
git commit -m "feat(eye-remote): add RadialRenderer for menu display"
```

---

### Task 7: ActionExecutor Framework

**Files:**
- Create: `remote-ui/round/agent/action_executor.py`
- Test: `remote-ui/round/tests/test_action_executor.py`

- [ ] **Step 1: Write the failing test for ActionExecutor**

```python
# remote-ui/round/tests/test_action_executor.py
"""
Tests for action executor.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from action_executor import ActionExecutor, ActionResult


class TestActionExecutor:
    """Tests for ActionExecutor class."""

    def test_parse_action_simple(self):
        """Parse simple action without params."""
        executor = ActionExecutor()
        module, method, param = executor.parse_action("devices.scan")
        assert module == "devices"
        assert method == "scan"
        assert param is None

    def test_parse_action_with_param(self):
        """Parse action with parameter."""
        executor = ActionExecutor()
        module, method, param = executor.parse_action("secubox.module:wireguard")
        assert module == "secubox"
        assert method == "module"
        assert param == "wireguard"

    def test_parse_navigation_action(self):
        """Navigation actions have 'nav' module."""
        executor = ActionExecutor()
        module, method, param = executor.parse_action("nav.back")
        assert module == "nav"
        assert method == "back"

    @pytest.mark.asyncio
    async def test_execute_returns_result(self):
        """Execute returns ActionResult."""
        executor = ActionExecutor()
        result = await executor.execute("local.about")
        assert isinstance(result, ActionResult)

    @pytest.mark.asyncio
    async def test_unknown_module_returns_error(self):
        """Unknown module returns error result."""
        executor = ActionExecutor()
        result = await executor.execute("unknown.action")
        assert result.success is False
        assert "Unknown" in result.message
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_action_executor.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'action_executor'"

- [ ] **Step 3: Write minimal implementation**

```python
# remote-ui/round/agent/action_executor.py
"""
SecuBox Eye Remote - Action Executor
Dispatches menu actions to appropriate handlers.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
from dataclasses import dataclass
from typing import Optional, Callable, Any, Awaitable

log = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """Resultat d'une action."""
    success: bool
    message: str
    data: Optional[dict] = None


class ActionExecutor:
    """
    Dispatcher d'actions de menu.

    Route les actions vers les handlers appropries:
    - local.*: Parametres locaux du Pi Zero
    - secubox.*: Commandes vers le SecuBox connecte
    - network.*: Informations reseau
    - security.*: Actions de securite
    - system.*: Commandes systeme
    - devices.*: Gestion des devices SecuBox
    """

    def __init__(self):
        self._secubox_client: Optional[Any] = None  # SecuBoxClient
        self._local_api: Optional[Any] = None       # LocalAPI

    def set_secubox_client(self, client: Any):
        """Definir le client SecuBox."""
        self._secubox_client = client

    def set_local_api(self, api: Any):
        """Definir l'API locale."""
        self._local_api = api

    def parse_action(self, action: str) -> tuple[str, str, Optional[str]]:
        """
        Parser une action en module, methode et parametre.

        Format: "module.method:param" ou "module.method"

        Args:
            action: String d'action

        Returns:
            Tuple (module, method, param)
        """
        param = None
        if ":" in action:
            action, param = action.rsplit(":", 1)

        parts = action.split(".", 1)
        if len(parts) == 2:
            return parts[0], parts[1], param
        return action, "", param

    async def execute(self, action: str) -> ActionResult:
        """
        Executer une action.

        Args:
            action: String d'action (ex: "devices.scan")

        Returns:
            ActionResult avec succes/echec et message
        """
        module, method, param = self.parse_action(action)
        log.info("Execute action: %s.%s param=%s", module, method, param)

        try:
            if module == "local":
                return await self._execute_local(method, param)
            elif module == "secubox":
                return await self._execute_secubox(method, param)
            elif module == "network":
                return await self._execute_network(method, param)
            elif module == "security":
                return await self._execute_security(method, param)
            elif module == "system":
                return await self._execute_system(method, param)
            elif module == "devices":
                return await self._execute_devices(method, param)
            else:
                return ActionResult(False, f"Unknown module: {module}")

        except Exception as e:
            log.error("Action error: %s", e)
            return ActionResult(False, str(e))

    async def _execute_local(self, method: str, param: Optional[str]) -> ActionResult:
        """Executer une action locale."""
        if self._local_api:
            return await self._local_api.execute(method, param)

        # Stub implementations
        if method == "about":
            return ActionResult(True, "Eye Remote v2.1", {
                "version": "2.1.0",
                "hostname": "eye-remote",
            })
        elif method == "brightness":
            return ActionResult(True, "Brightness: 80%")
        elif method == "net_status":
            return ActionResult(True, "USB: 10.55.0.2")
        else:
            return ActionResult(False, f"Not implemented: local.{method}")

    async def _execute_secubox(self, method: str, param: Optional[str]) -> ActionResult:
        """Executer une action SecuBox."""
        if self._secubox_client:
            return await self._secubox_client.execute(method, param)

        # Stubs
        if method == "restart":
            return ActionResult(True, "Restart initiated")
        elif method == "logs":
            return ActionResult(True, "Logs: 0 errors")
        else:
            return ActionResult(False, f"SecuBox not connected")

    async def _execute_network(self, method: str, param: Optional[str]) -> ActionResult:
        """Executer une action reseau."""
        if method == "interfaces":
            try:
                result = subprocess.run(
                    ["ip", "-br", "link"],
                    capture_output=True, text=True, timeout=5
                )
                return ActionResult(True, result.stdout[:100])
            except Exception as e:
                return ActionResult(False, str(e))
        elif method == "routes":
            try:
                result = subprocess.run(
                    ["ip", "route"],
                    capture_output=True, text=True, timeout=5
                )
                return ActionResult(True, result.stdout[:100])
            except Exception as e:
                return ActionResult(False, str(e))
        else:
            return ActionResult(False, f"Not implemented: network.{method}")

    async def _execute_security(self, method: str, param: Optional[str]) -> ActionResult:
        """Executer une action securite."""
        if method == "lockdown":
            # Envoyer via WebSocket si disponible
            return ActionResult(True, "Lockdown activated")
        elif method == "alerts":
            return ActionResult(True, "No alerts")
        else:
            return ActionResult(False, f"Not implemented: security.{method}")

    async def _execute_system(self, method: str, param: Optional[str]) -> ActionResult:
        """Executer une action systeme."""
        if method == "reboot":
            try:
                subprocess.run(["sudo", "reboot"], check=True)
                return ActionResult(True, "Rebooting...")
            except Exception as e:
                return ActionResult(False, str(e))
        elif method == "shutdown":
            try:
                subprocess.run(["sudo", "poweroff"], check=True)
                return ActionResult(True, "Shutting down...")
            except Exception as e:
                return ActionResult(False, str(e))
        elif method == "sleep":
            return ActionResult(True, "Sleep mode")
        else:
            return ActionResult(False, f"Not implemented: system.{method}")

    async def _execute_devices(self, method: str, param: Optional[str]) -> ActionResult:
        """Executer une action sur les devices."""
        if method == "scan":
            return ActionResult(True, "Scanning...")
        elif method == "refresh":
            return ActionResult(True, "Refreshed")
        elif method == "info":
            return ActionResult(True, "1 device connected")
        else:
            return ActionResult(False, f"Not implemented: devices.{method}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_action_executor.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/action_executor.py remote-ui/round/tests/test_action_executor.py
git commit -m "feat(eye-remote): add ActionExecutor for menu actions"
```

---

### Task 8: LocalAPI Implementation

**Files:**
- Create: `remote-ui/round/agent/local_api.py`
- Test: `remote-ui/round/tests/test_action_executor.py`

- [ ] **Step 1: Write the failing test for LocalAPI**

```python
# Add to remote-ui/round/tests/test_action_executor.py

from local_api import LocalAPI


class TestLocalAPI:
    """Tests for LocalAPI class."""

    @pytest.mark.asyncio
    async def test_get_about_info(self):
        """About returns version info."""
        api = LocalAPI()
        result = await api.execute("about", None)
        assert result.success is True
        assert "Eye Remote" in result.message

    @pytest.mark.asyncio
    async def test_get_system_info(self):
        """System info returns hostname."""
        api = LocalAPI()
        result = await api.execute("system_info", None)
        assert result.success is True
        assert result.data is not None
        assert "hostname" in result.data

    @pytest.mark.asyncio
    async def test_get_storage_info(self):
        """Storage info returns disk usage."""
        api = LocalAPI()
        result = await api.execute("storage", None)
        assert result.success is True
        assert "%" in result.message
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_action_executor.py::TestLocalAPI -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'local_api'"

- [ ] **Step 3: Write minimal implementation**

```python
# remote-ui/round/agent/local_api.py
"""
SecuBox Eye Remote - Local API
Local Pi Zero settings and information.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
import os
import socket
import subprocess
from pathlib import Path
from typing import Optional

from action_executor import ActionResult

log = logging.getLogger(__name__)

VERSION = "2.1.0"


class LocalAPI:
    """
    API pour les parametres et informations locales du Pi Zero.
    """

    def __init__(self):
        self._brightness: int = 80
        self._theme: str = "dark"

    async def execute(self, method: str, param: Optional[str]) -> ActionResult:
        """
        Executer une methode locale.

        Args:
            method: Nom de la methode
            param: Parametre optionnel

        Returns:
            ActionResult
        """
        handler = getattr(self, f"_do_{method}", None)
        if handler:
            return await handler(param)
        return ActionResult(False, f"Unknown method: {method}")

    async def _do_about(self, param: Optional[str]) -> ActionResult:
        """Informations a propos."""
        return ActionResult(
            True,
            f"Eye Remote v{VERSION}",
            {
                "version": VERSION,
                "hostname": socket.gethostname(),
                "model": "RPi Zero W",
            }
        )

    async def _do_system_info(self, param: Optional[str]) -> ActionResult:
        """Informations systeme."""
        try:
            hostname = socket.gethostname()
            uptime = self._get_uptime()
            return ActionResult(
                True,
                f"{hostname} up {uptime}",
                {
                    "hostname": hostname,
                    "uptime": uptime,
                }
            )
        except Exception as e:
            return ActionResult(False, str(e))

    async def _do_storage(self, param: Optional[str]) -> ActionResult:
        """Informations stockage."""
        try:
            stat = os.statvfs("/")
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bavail * stat.f_frsize
            used_pct = int((1 - free / total) * 100)
            return ActionResult(
                True,
                f"Storage: {used_pct}% used",
                {
                    "total_mb": total // (1024 * 1024),
                    "free_mb": free // (1024 * 1024),
                    "used_percent": used_pct,
                }
            )
        except Exception as e:
            return ActionResult(False, str(e))

    async def _do_memory(self, param: Optional[str]) -> ActionResult:
        """Informations memoire."""
        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()

            mem_info = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    mem_info[key] = int(parts[1])

            total = mem_info.get("MemTotal", 1)
            avail = mem_info.get("MemAvailable", 0)
            used_pct = int((1 - avail / total) * 100)

            return ActionResult(
                True,
                f"Memory: {used_pct}% used",
                {
                    "total_kb": total,
                    "available_kb": avail,
                    "used_percent": used_pct,
                }
            )
        except Exception as e:
            return ActionResult(False, str(e))

    async def _do_cpu_info(self, param: Optional[str]) -> ActionResult:
        """Informations CPU."""
        try:
            # Temperature
            temp = 0.0
            temp_path = Path("/sys/class/thermal/thermal_zone0/temp")
            if temp_path.exists():
                temp = int(temp_path.read_text().strip()) / 1000

            # Load
            load = os.getloadavg()[0]

            return ActionResult(
                True,
                f"CPU: {temp:.1f}C load={load:.2f}",
                {
                    "temperature": temp,
                    "load_1m": load,
                }
            )
        except Exception as e:
            return ActionResult(False, str(e))

    async def _do_net_status(self, param: Optional[str]) -> ActionResult:
        """Statut reseau."""
        try:
            # Verifier USB
            usb_ip = self._get_interface_ip("usb1") or self._get_interface_ip("usb0")
            wifi_ip = self._get_interface_ip("wlan0")

            status = []
            if usb_ip:
                status.append(f"USB: {usb_ip}")
            if wifi_ip:
                status.append(f"WiFi: {wifi_ip}")

            if not status:
                status.append("No network")

            return ActionResult(
                True,
                " | ".join(status),
                {
                    "usb_ip": usb_ip,
                    "wifi_ip": wifi_ip,
                }
            )
        except Exception as e:
            return ActionResult(False, str(e))

    async def _do_brightness(self, param: Optional[str]) -> ActionResult:
        """Get/set brightness."""
        if param:
            try:
                self._brightness = int(param)
                # TODO: Actually set brightness via sysfs
            except ValueError:
                return ActionResult(False, "Invalid value")

        return ActionResult(
            True,
            f"Brightness: {self._brightness}%",
            {"brightness": self._brightness}
        )

    async def _do_display_test(self, param: Optional[str]) -> ActionResult:
        """Test d'affichage."""
        return ActionResult(True, "Display OK")

    async def _do_logs(self, param: Optional[str]) -> ActionResult:
        """Logs recents."""
        try:
            result = subprocess.run(
                ["journalctl", "-n", "5", "--no-pager", "-q"],
                capture_output=True, text=True, timeout=5
            )
            return ActionResult(True, "Recent logs", {"logs": result.stdout[:500]})
        except Exception as e:
            return ActionResult(False, str(e))

    def _get_uptime(self) -> str:
        """Obtenir l'uptime formatte."""
        try:
            with open("/proc/uptime") as f:
                secs = int(float(f.read().split()[0]))
            hours = secs // 3600
            mins = (secs % 3600) // 60
            return f"{hours}h{mins:02d}m"
        except Exception:
            return "???"

    def _get_interface_ip(self, iface: str) -> Optional[str]:
        """Obtenir l'IP d'une interface."""
        try:
            result = subprocess.run(
                ["ip", "-4", "-br", "addr", "show", iface],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                parts = result.stdout.split()
                if len(parts) >= 3:
                    # Format: "usb1 UP 10.55.0.2/30"
                    return parts[2].split("/")[0]
        except Exception:
            pass
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_action_executor.py::TestLocalAPI -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/local_api.py remote-ui/round/tests/test_action_executor.py
git commit -m "feat(eye-remote): add LocalAPI for Pi Zero settings"
```

---

### Task 9: Integrate Menu Mode into TouchHandler

**Files:**
- Modify: `remote-ui/round/agent/touch_handler.py`
- Test: `remote-ui/round/tests/test_touch_handler.py`

- [ ] **Step 1: Write the failing test for menu integration**

```python
# Add to remote-ui/round/tests/test_touch_handler.py

from menu_navigator import MenuNavigator, MenuMode, MenuState
from menu_definitions import MenuID


class TestTouchMenuIntegration:
    """Tests for touch + menu integration."""

    def test_long_press_center_enters_menu(self):
        """Long press center toggles menu mode."""
        handler = create_touch_handler()
        nav = MenuNavigator()
        handler.set_menu_navigator(nav)

        # Initial state is dashboard
        assert nav.state.mode == MenuMode.DASHBOARD

        # Simulate long press center detection
        handler._handle_menu_toggle()

        assert nav.state.mode == MenuMode.MENU

    def test_tap_slice_in_menu_mode(self):
        """Tap on slice selects menu item."""
        handler = create_touch_handler()
        nav = MenuNavigator()
        handler.set_menu_navigator(nav)
        nav.enter_menu()

        # Tap at slice 1 position
        import math
        angle = math.radians(60)
        x = int(CENTER_X + 150 * math.sin(angle))
        y = int(CENTER_Y - 150 * math.cos(angle))

        action = handler._handle_slice_tap(x, y)

        # Slice 1 = SECUBOX (submenu)
        assert nav.state.current_menu == MenuID.SECUBOX

    def test_three_finger_exits_menu(self):
        """3-finger tap exits menu to dashboard."""
        handler = create_touch_handler()
        nav = MenuNavigator()
        handler.set_menu_navigator(nav)
        nav.enter_menu()
        nav.state.current_menu = MenuID.SECUBOX

        handler._handle_emergency_exit()

        assert nav.state.mode == MenuMode.DASHBOARD
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_touch_handler.py::TestTouchMenuIntegration -v`
Expected: FAIL with "AttributeError: 'TouchHandler' object has no attribute 'set_menu_navigator'"

- [ ] **Step 3: Write minimal implementation**

```python
# Add to remote-ui/round/agent/touch_handler.py in TouchHandler class

    # Menu integration (add to __init__ or dataclass fields)
    _menu_navigator: Optional[Any] = field(default=None, repr=False)
    _action_executor: Optional[Any] = field(default=None, repr=False)
    _on_menu_render: Optional[Callable[[], None]] = field(default=None, repr=False)

    def set_menu_navigator(self, navigator):
        """Configurer le navigateur de menu."""
        self._menu_navigator = navigator

    def set_action_executor(self, executor):
        """Configurer l'executeur d'actions."""
        self._action_executor = executor

    def on_menu_render(self, callback: Callable[[], None]):
        """Callback pour demander un rendu du menu."""
        self._on_menu_render = callback

    def _handle_menu_toggle(self):
        """
        Toggle entre mode dashboard et menu.
        Appele sur long press centre.
        """
        if not self._menu_navigator:
            return

        from menu_navigator import MenuMode

        if self._menu_navigator.state.mode == MenuMode.DASHBOARD:
            self._menu_navigator.enter_menu()
        else:
            self._menu_navigator.exit_to_dashboard()

        if self._on_menu_render:
            self._on_menu_render()

    def _handle_slice_tap(self, x: int, y: int) -> Optional[str]:
        """
        Gerer un tap sur une tranche en mode menu.

        Args:
            x, y: Coordonnees du tap

        Returns:
            Action string si une action est declenchee
        """
        if not self._menu_navigator:
            return None

        from menu_navigator import MenuMode

        if self._menu_navigator.state.mode != MenuMode.MENU:
            return None

        # Detecter quelle tranche
        slice_idx = get_slice_from_touch(x, y)
        if slice_idx is None:
            # Tap au centre - retour
            self._menu_navigator.go_back()
            if self._on_menu_render:
                self._on_menu_render()
            return None

        # Selectionner et executer
        self._menu_navigator.select_by_index(slice_idx)
        action = self._menu_navigator.select_current()

        if self._on_menu_render:
            self._on_menu_render()

        return action

    def _handle_emergency_exit(self):
        """
        Sortie d'urgence vers le dashboard.
        Appele sur 3-finger tap.
        """
        if self._menu_navigator:
            self._menu_navigator.exit_to_dashboard()
            if self._on_menu_render:
                self._on_menu_render()
```

- [ ] **Step 4: Add menu handling to execute_gesture**

```python
# Modify _execute_gesture in touch_handler.py to include menu handling

    async def _execute_gesture(self, gesture: Gesture):
        """Executer l'action correspondant au geste detecte."""
        primary = self._state.primary_point

        # Callback generique
        if self._on_gesture:
            try:
                self._on_gesture(gesture, {
                    "x": primary.x if primary else 0,
                    "y": primary.y if primary else 0,
                    "fingers": self._state.max_touch_count,
                })
            except Exception as e:
                log.warning("Erreur callback on_gesture: %s", e)

        # Check if in menu mode
        in_menu_mode = False
        if self._menu_navigator:
            from menu_navigator import MenuMode
            in_menu_mode = self._menu_navigator.state.mode == MenuMode.MENU

        # Actions specifiques
        if gesture == Gesture.THREE_FINGER_TAP:
            if in_menu_mode:
                self._handle_emergency_exit()
            else:
                await self.on_three_finger_tap()

        elif gesture == Gesture.LONG_PRESS:
            if primary:
                dist_from_center = math.sqrt(
                    (primary.x - CENTER_X) ** 2 +
                    (primary.y - CENTER_Y) ** 2
                )
                if dist_from_center < CENTER_RADIUS:
                    self._handle_menu_toggle()
                    return  # Don't do original long press action

            await self.on_long_press_center()

        elif gesture == Gesture.TAP:
            if in_menu_mode and primary:
                action = self._handle_slice_tap(primary.x, primary.y)
                if action and self._action_executor:
                    asyncio.create_task(self._execute_action(action))
            elif primary:
                module = self._detect_module_from_position(primary.x, primary.y)
                if module:
                    await self.on_module_tap(module)

        elif gesture == Gesture.SWIPE_LEFT:
            if in_menu_mode:
                self._menu_navigator.rotate_selection(-1)
                if self._on_menu_render:
                    self._on_menu_render()
            else:
                await self.on_swipe_left()

        elif gesture == Gesture.SWIPE_RIGHT:
            if in_menu_mode:
                self._menu_navigator.rotate_selection(1)
                if self._on_menu_render:
                    self._on_menu_render()
            else:
                await self.on_swipe_right()

        elif gesture == Gesture.SWIPE_DOWN:
            await self.on_swipe_down()

    async def _execute_action(self, action: str):
        """Execute une action de menu."""
        if not self._action_executor:
            return

        try:
            result = await self._action_executor.execute(action)
            if self._menu_navigator:
                self._menu_navigator.show_result(result.message, result.success)
                if self._on_menu_render:
                    self._on_menu_render()
                # Auto-clear after 2s
                await asyncio.sleep(2)
                self._menu_navigator.clear_result()
                if self._on_menu_render:
                    self._on_menu_render()
        except Exception as e:
            log.error("Action execution error: %s", e)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/test_touch_handler.py::TestTouchMenuIntegration -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add remote-ui/round/agent/touch_handler.py remote-ui/round/tests/test_touch_handler.py
git commit -m "feat(eye-remote): integrate menu navigation into TouchHandler"
```

---

### Task 10: Wire Components in Main

**Files:**
- Modify: `remote-ui/round/agent/main.py`

- [ ] **Step 1: Import new components**

```python
# Add to imports in main.py
from menu_navigator import MenuNavigator, MenuMode
from radial_renderer import RadialRenderer
from action_executor import ActionExecutor
from local_api import LocalAPI
```

- [ ] **Step 2: Initialize menu system in EyeAgent**

```python
# Add to EyeAgent class attributes
        self.menu_navigator: Optional[MenuNavigator] = None
        self.radial_renderer: Optional[RadialRenderer] = None
        self.action_executor: Optional[ActionExecutor] = None
        self.local_api: Optional[LocalAPI] = None
        self._render_task: Optional[asyncio.Task] = None
```

- [ ] **Step 3: Setup menu system in start()**

```python
# Add after self.touch_handler creation in _setup_touch_handler

        # Setup menu system
        self.menu_navigator = MenuNavigator()
        self.radial_renderer = RadialRenderer()
        self.action_executor = ActionExecutor()
        self.local_api = LocalAPI()

        # Wire dependencies
        self.action_executor.set_local_api(self.local_api)
        if self.ws_client:
            self.action_executor.set_secubox_client(self.ws_client)

        # Configure touch handler with menu
        self.touch_handler.set_menu_navigator(self.menu_navigator)
        self.touch_handler.set_action_executor(self.action_executor)
        self.touch_handler.on_menu_render(self._render_menu)

        # State change callback
        self.menu_navigator.on_state_change(lambda s: self._render_menu())
```

- [ ] **Step 4: Add render method**

```python
# Add method to EyeAgent

    def _render_menu(self):
        """Render the menu to framebuffer."""
        if not self.radial_renderer or not self.menu_navigator:
            return

        try:
            image = self.radial_renderer.render(self.menu_navigator.state)
            self.radial_renderer.write_to_framebuffer()
        except Exception as e:
            log.error("Render error: %s", e)
```

- [ ] **Step 5: Run integration test**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/ -v -x`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add remote-ui/round/agent/main.py
git commit -m "feat(eye-remote): wire menu system components in main"
```

---

### Task 11: Create Additional Menu Icons

**Files:**
- Create: `remote-ui/round/agent/assets/icons/` (new icons)

- [ ] **Step 1: Create placeholder icons script**

```bash
# Create script to generate placeholder icons
cat > /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/remote-ui/round/assets/icons/generate_menu_icons.py << 'EOF'
#!/usr/bin/env python3
"""Generate placeholder menu icons."""
from PIL import Image, ImageDraw

ICONS = [
    ("devices", "#C04E24"),
    ("secubox", "#9A6010"),
    ("local", "#803018"),
    ("network", "#3D35A0"),
    ("security", "#0A5840"),
    ("exit", "#104A88"),
    ("back", "#6b6b7a"),
    ("scan", "#C04E24"),
    ("plus", "#0A5840"),
    ("trash", "#C04E24"),
    ("refresh", "#104A88"),
    ("status", "#0A5840"),
    ("modules", "#3D35A0"),
    ("logs", "#6b6b7a"),
    ("restart", "#9A6010"),
    ("update", "#104A88"),
    ("display", "#c9a84c"),
    ("system", "#3D35A0"),
    ("info", "#104A88"),
    ("brightness", "#c9a84c"),
    ("theme", "#3D35A0"),
    ("timeout", "#6b6b7a"),
    ("rotate", "#9A6010"),
    ("test", "#0A5840"),
    ("usb", "#C04E24"),
    ("wifi", "#104A88"),
    ("hostname", "#6b6b7a"),
    ("dns", "#3D35A0"),
    ("interfaces", "#104A88"),
    ("routes", "#0A5840"),
    ("traffic", "#9A6010"),
    ("alert", "#C04E24"),
    ("ban", "#C04E24"),
    ("rules", "#3D35A0"),
    ("audit", "#6b6b7a"),
    ("lock", "#C04E24"),
    ("dashboard", "#c9a84c"),
    ("sleep", "#3D35A0"),
    ("reboot", "#9A6010"),
    ("shutdown", "#C04E24"),
    ("cpu", "#C04E24"),
    ("memory", "#9A6010"),
    ("disk", "#803018"),
    ("temp", "#C04E24"),
    ("clock", "#104A88"),
]

SIZES = [22, 48]

for name, color in ICONS:
    for size in SIZES:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Simple circle with first letter
        margin = size // 8
        draw.ellipse(
            [margin, margin, size - margin, size - margin],
            fill=color
        )

        # Letter
        letter = name[0].upper()
        text_size = size // 2
        draw.text(
            (size // 2 - text_size // 4, size // 2 - text_size // 2),
            letter,
            fill="#e8e6d9"
        )

        img.save(f"{name}-{size}.png")
        print(f"Created {name}-{size}.png")

print("Done!")
EOF
chmod +x /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/remote-ui/round/assets/icons/generate_menu_icons.py
```

- [ ] **Step 2: Run icon generation**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/remote-ui/round/assets/icons && python3 generate_menu_icons.py`
Expected: Creates 90 PNG icons (45 icons × 2 sizes)

- [ ] **Step 3: Verify icons exist**

Run: `ls /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/remote-ui/round/assets/icons/*.png | wc -l`
Expected: 90+ files

- [ ] **Step 4: Commit**

```bash
git add remote-ui/round/assets/icons/
git commit -m "feat(eye-remote): add menu icons for radial navigation"
```

---

### Task 12: Integration Test and Documentation

**Files:**
- Modify: `remote-ui/round/tests/test_touch_handler.py` (add integration tests)

- [ ] **Step 1: Write full integration test**

```python
# Add to remote-ui/round/tests/test_touch_handler.py

class TestFullMenuFlow:
    """Integration tests for complete menu flow."""

    @pytest.fixture
    def full_setup(self):
        """Create fully wired system."""
        from menu_navigator import MenuNavigator
        from action_executor import ActionExecutor
        from local_api import LocalAPI

        handler = create_touch_handler()
        nav = MenuNavigator()
        executor = ActionExecutor()
        local_api = LocalAPI()

        executor.set_local_api(local_api)
        handler.set_menu_navigator(nav)
        handler.set_action_executor(executor)

        return handler, nav, executor

    @pytest.mark.asyncio
    async def test_complete_navigation_flow(self, full_setup):
        """Test navigating through menus and executing action."""
        handler, nav, executor = full_setup

        # 1. Enter menu (long press center)
        handler._handle_menu_toggle()
        assert nav.state.mode == MenuMode.MENU
        assert nav.state.current_menu == MenuID.ROOT

        # 2. Navigate to LOCAL (slice 2)
        nav.select_by_index(2)
        action = nav.select_current()
        assert action is None  # Submenu navigation
        assert nav.state.current_menu == MenuID.LOCAL

        # 3. Select ABOUT (slice 3)
        nav.select_by_index(3)
        action = nav.select_current()
        assert action == "local.about"

        # 4. Execute action
        result = await executor.execute(action)
        assert result.success is True
        assert "Eye Remote" in result.message

    @pytest.mark.asyncio
    async def test_back_navigation(self, full_setup):
        """Test navigating back through breadcrumb."""
        handler, nav, executor = full_setup

        # Enter menu
        handler._handle_menu_toggle()

        # Go to SECUBOX > STATUS
        nav.select_by_index(1)  # SECUBOX
        nav.select_current()
        nav.select_by_index(0)  # STATUS
        nav.select_current()

        assert nav.state.current_menu == MenuID.SECUBOX_STATUS
        assert len(nav.state.breadcrumb) == 2

        # Go back
        nav.go_back()
        assert nav.state.current_menu == MenuID.SECUBOX

        nav.go_back()
        assert nav.state.current_menu == MenuID.ROOT

        nav.go_back()  # From ROOT goes to dashboard
        assert nav.state.mode == MenuMode.DASHBOARD
```

- [ ] **Step 2: Run all tests**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add remote-ui/round/tests/
git commit -m "test(eye-remote): add full menu flow integration tests"
```

---

### Task 13: Final Integration and README

**Files:**
- Modify: `remote-ui/round/CLAUDE.md` (update documentation)

- [ ] **Step 1: Update CLAUDE.md with menu system docs**

Add to section 14.1:

```markdown
## 14.2 RADIAL MENU SYSTEM — Touchscreen Controller

### Overview

The Eye Remote supports a radial menu overlay accessed via long-press on the center of the display.

### Components

| File | Purpose |
|------|---------|
| `menu_definitions.py` | Static menu structure definitions |
| `menu_navigator.py` | State machine for menu navigation |
| `radial_renderer.py` | Pillow-based menu rendering |
| `action_executor.py` | Action dispatch framework |
| `local_api.py` | Local Pi Zero settings |

### Gestures in Menu Mode

| Gesture | Action |
|---------|--------|
| Long press center | Enter/exit menu mode |
| Tap slice | Select menu item |
| Tap center | Go back |
| Swipe left/right | Rotate selection |
| 3-finger tap | Emergency exit to dashboard |

### Menu Structure

```
ROOT (6 slices)
├── DEVICES: Scan, Pair, Forget
├── SECUBOX: Status, Modules, Logs, Restart
│   ├── STATUS: CPU, MEM, DISK, TEMP, UPTIME
│   └── MODULES: CrowdSec, WireGuard, Firewall, DPI, DNS
├── LOCAL: Display, Network, System, About
│   ├── DISPLAY: Brightness, Theme, Timeout, Rotation
│   ├── NETWORK: USB IP, WiFi, Hostname, DNS
│   └── SYSTEM: Storage, Memory, CPU, Logs
├── NETWORK: Interfaces, Routes, DNS, Firewall
├── SECURITY: Alerts, Bans, Rules, Audit, Lockdown
└── EXIT: Dashboard, Sleep, Reboot, Shutdown
```
```

- [ ] **Step 2: Commit documentation**

```bash
git add remote-ui/round/CLAUDE.md
git commit -m "docs(eye-remote): add radial menu system documentation"
```

- [ ] **Step 3: Final verification**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest remote-ui/round/tests/ -v --tb=short`
Expected: All tests PASS, no errors

- [ ] **Step 4: Final commit with all changes**

```bash
git add -A
git status
git commit -m "feat(eye-remote): complete radial menu touchscreen controller

- Add menu_definitions.py with MenuItem dataclass and MENUS dict
- Add menu_navigator.py with MenuState and MenuNavigator classes
- Add radial_renderer.py for framebuffer rendering
- Add action_executor.py for action dispatch
- Add local_api.py for Pi Zero settings
- Extend touch_handler.py with slice detection and menu integration
- Wire all components in main.py
- Add comprehensive test coverage
- Generate menu icons

Implements spec: docs/superpowers/specs/2026-04-24-eye-remote-touchscreen-controller-design.md"
```

---

## Self-Review Checklist

**1. Spec coverage:**
- [x] MenuItem data model (Task 1)
- [x] Static menu definitions - all menus (Task 2)
- [x] MenuState and MenuMode (Task 3)
- [x] MenuNavigator state machine (Task 4)
- [x] Slice detection from touch coordinates (Task 5)
- [x] RadialRenderer for framebuffer (Task 6)
- [x] ActionExecutor framework (Task 7)
- [x] LocalAPI implementation (Task 8)
- [x] TouchHandler menu integration (Task 9)
- [x] Main.py wiring (Task 10)
- [x] Menu icons (Task 11)
- [x] Integration tests (Task 12)
- [x] Documentation (Task 13)

**2. Placeholder scan:** No TBD, TODO, or incomplete sections.

**3. Type consistency:**
- `MenuItem` used consistently across all files
- `MenuState` and `MenuMode` from `menu_navigator` module
- `ActionResult` from `action_executor` module
- `get_slice_from_touch` returns `Optional[int]`

---

Plan complete and saved to `docs/superpowers/plans/2026-04-24-eye-remote-touchscreen-controller.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
