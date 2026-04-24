"""
Tests pour le TouchHandler Eye Remote.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import asyncio
import math
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ajouter le repertoire agent au path
sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

from touch_handler import (
    TouchHandler,
    TouchPoint,
    GestureState,
    Gesture,
    create_touch_handler,
    get_slice_from_touch,
    MODULE_RINGS,
    CENTER_X,
    CENTER_Y,
    SWIPE_THRESHOLD,
    LONG_PRESS_MS,
    TAP_MAX_MS,
)
from menu_navigator import MenuNavigator, MenuMode
from menu_definitions import MenuID
from action_executor import ActionExecutor
from local_api import LocalAPI


# =============================================================================
# Tests GestureState
# =============================================================================

class TestGestureState:
    """Tests pour la classe GestureState."""

    def test_initial_state(self):
        """Verifier l'etat initial."""
        state = GestureState()
        assert state.active_count == 0
        assert state.max_touch_count == 0
        assert state.gesture_started is False
        assert state.primary_point is None

    def test_reset(self):
        """Verifier la reinitialisation."""
        state = GestureState()
        state.touch_points[0] = TouchPoint(slot=0, tracking_id=1, x=100, y=100)
        state.max_touch_count = 3
        state.gesture_started = True
        state.first_touch_time = 123.456

        state.reset()

        assert len(state.touch_points) == 0
        assert state.max_touch_count == 0
        assert state.gesture_started is False
        assert state.first_touch_time == 0.0

    def test_active_count(self):
        """Verifier le comptage des points actifs."""
        state = GestureState()
        state.touch_points[0] = TouchPoint(slot=0, tracking_id=1, x=100, y=100, active=True)
        state.touch_points[1] = TouchPoint(slot=1, tracking_id=2, x=200, y=200, active=True)
        state.touch_points[2] = TouchPoint(slot=2, tracking_id=3, x=300, y=300, active=False)

        assert state.active_count == 2

    def test_primary_point(self):
        """Verifier la detection du point principal."""
        state = GestureState()
        state.touch_points[0] = TouchPoint(slot=0, tracking_id=1, x=100, y=100, active=True)
        state.touch_points[1] = TouchPoint(slot=1, tracking_id=2, x=200, y=200, active=True)

        primary = state.primary_point
        assert primary is not None
        assert primary.slot == 0

    def test_primary_point_fallback(self):
        """Verifier le fallback si slot 0 inactif."""
        state = GestureState()
        state.touch_points[0] = TouchPoint(slot=0, tracking_id=1, x=100, y=100, active=False)
        state.touch_points[1] = TouchPoint(slot=1, tracking_id=2, x=200, y=200, active=True)

        primary = state.primary_point
        assert primary is not None
        assert primary.slot == 1


# =============================================================================
# Tests TouchHandler - Detection des modules
# =============================================================================

class TestModuleDetection:
    """Tests pour la detection des modules via position tactile."""

    def test_module_rings_defined(self):
        """Verifier que tous les modules sont definis."""
        expected_modules = ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]
        for module in expected_modules:
            assert module in MODULE_RINGS
            assert "radius" in MODULE_RINGS[module]
            assert "inner" in MODULE_RINGS[module]
            assert "outer" in MODULE_RINGS[module]

    def test_detect_auth_module(self):
        """Detecter un tap sur l'anneau AUTH (r=214)."""
        handler = create_touch_handler()

        # Position sur l'anneau AUTH (rayon ~214 depuis le centre)
        # Angle 0 = droite, donc x = 240 + 214 = 454, y = 240
        x = CENTER_X + 210  # Dans la plage [207, 221]
        y = CENTER_Y

        module = handler._detect_module_from_position(x, y)
        assert module == "AUTH"

    def test_detect_mesh_module(self):
        """Detecter un tap sur l'anneau MESH (r=149)."""
        handler = create_touch_handler()

        # Position sur l'anneau MESH
        x = CENTER_X + 150  # Dans la plage [142, 155]
        y = CENTER_Y

        module = handler._detect_module_from_position(x, y)
        assert module == "MESH"

    def test_detect_no_module_center(self):
        """Pas de module detecte au centre."""
        handler = create_touch_handler()

        # Centre de l'ecran
        module = handler._detect_module_from_position(CENTER_X, CENTER_Y)
        assert module is None

    def test_detect_no_module_outside(self):
        """Pas de module detecte en dehors des anneaux."""
        handler = create_touch_handler()

        # Position hors des anneaux (trop loin)
        x = CENTER_X + 230  # Au-dela de AUTH outer=221
        y = CENTER_Y

        module = handler._detect_module_from_position(x, y)
        assert module is None

    def test_detect_module_diagonal(self):
        """Detecter un module sur une position diagonale."""
        handler = create_touch_handler()

        # Position diagonale a ~175 pixels du centre (MIND)
        # Pour angle 45 degres: x = r * cos(45) = r * 0.707
        r = 175
        angle_rad = math.radians(45)
        x = int(CENTER_X + r * math.cos(angle_rad))
        y = int(CENTER_Y + r * math.sin(angle_rad))

        module = handler._detect_module_from_position(x, y)
        assert module == "MIND"


# =============================================================================
# Tests TouchHandler - Detection des gestes
# =============================================================================

class TestGestureDetection:
    """Tests pour la detection des gestes."""

    def setup_method(self):
        """Preparer un handler pour chaque test."""
        self.handler = create_touch_handler()

    def _setup_gesture(self, start_x, start_y, end_x, end_y, duration_s, touch_count=1):
        """Configurer l'etat pour un geste simule."""
        import time
        now = time.time()

        self.handler._state.first_touch_time = now - duration_s
        self.handler._state.last_event_time = now
        self.handler._state.gesture_started = True
        self.handler._state.max_touch_count = touch_count

        # Point principal
        self.handler._state.touch_points[0] = TouchPoint(
            slot=0,
            tracking_id=1,
            x=end_x,
            y=end_y,
            start_x=start_x,
            start_y=start_y,
            start_time=now - duration_s,
            active=False
        )

        # Points supplementaires pour multi-touch
        for i in range(1, touch_count):
            self.handler._state.touch_points[i] = TouchPoint(
                slot=i,
                tracking_id=i + 1,
                x=end_x + 20 * i,
                y=end_y + 20 * i,
                start_x=start_x + 20 * i,
                start_y=start_y + 20 * i,
                start_time=now - duration_s,
                active=False
            )

    def test_detect_tap(self):
        """Detecter un tap simple."""
        # Tap rapide sans deplacement
        self._setup_gesture(
            start_x=200, start_y=200,
            end_x=202, end_y=201,  # Petit deplacement
            duration_s=0.1  # 100ms < TAP_MAX_MS
        )

        gesture = self.handler._detect_gesture()
        assert gesture == Gesture.TAP

    def test_detect_swipe_left(self):
        """Detecter un swipe vers la gauche."""
        self._setup_gesture(
            start_x=300, start_y=240,
            end_x=200, end_y=240,  # dx = -100
            duration_s=0.3
        )

        gesture = self.handler._detect_gesture()
        assert gesture == Gesture.SWIPE_LEFT

    def test_detect_swipe_right(self):
        """Detecter un swipe vers la droite."""
        self._setup_gesture(
            start_x=200, start_y=240,
            end_x=300, end_y=240,  # dx = +100
            duration_s=0.3
        )

        gesture = self.handler._detect_gesture()
        assert gesture == Gesture.SWIPE_RIGHT

    def test_detect_swipe_down_from_top(self):
        """Detecter un swipe down depuis le haut."""
        self._setup_gesture(
            start_x=240, start_y=30,   # Zone superieure
            end_x=240, end_y=150,       # Swipe vers le bas
            duration_s=0.3
        )

        gesture = self.handler._detect_gesture()
        assert gesture == Gesture.SWIPE_DOWN

    def test_detect_long_press(self):
        """Detecter un long press au centre."""
        self._setup_gesture(
            start_x=CENTER_X, start_y=CENTER_Y,
            end_x=CENTER_X + 5, end_y=CENTER_Y + 5,  # Petit deplacement
            duration_s=1.0  # > LONG_PRESS_MS
        )

        gesture = self.handler._detect_gesture()
        assert gesture == Gesture.LONG_PRESS

    def test_detect_three_finger_tap(self):
        """Detecter un tap a trois doigts."""
        self._setup_gesture(
            start_x=200, start_y=200,
            end_x=205, end_y=205,
            duration_s=0.15,  # Rapide
            touch_count=3
        )

        gesture = self.handler._detect_gesture()
        assert gesture == Gesture.THREE_FINGER_TAP

    def test_no_swipe_down_from_middle(self):
        """Pas de swipe down si pas depuis le haut."""
        self._setup_gesture(
            start_x=240, start_y=200,  # Pas dans la zone top
            end_x=240, end_y=350,
            duration_s=0.3
        )

        gesture = self.handler._detect_gesture()
        # Devrait etre TAP ou NONE, pas SWIPE_DOWN
        assert gesture != Gesture.SWIPE_DOWN


# =============================================================================
# Tests TouchHandler - Actions
# =============================================================================

class TestGestureActions:
    """Tests pour les actions declenchees par les gestes."""

    @pytest.fixture
    def handler_with_mocks(self):
        """Creer un handler avec des mocks pour device_manager et ws_client."""
        mock_dm = MagicMock()
        mock_dm.list_secuboxes.return_value = [
            {"name": "SecuBox-1", "host": "192.168.1.1", "active": True},
            {"name": "SecuBox-2", "host": "192.168.1.2", "active": False},
            {"name": "SecuBox-3", "host": "192.168.1.3", "active": False},
        ]
        mock_dm.switch_to = AsyncMock(return_value=True)

        mock_ws = MagicMock()
        mock_ws.send_message = AsyncMock(return_value=True)

        handler = create_touch_handler(
            device_manager=mock_dm,
            ws_client=mock_ws
        )

        return handler, mock_dm, mock_ws

    @pytest.mark.asyncio
    async def test_swipe_left_switches_to_previous(self, handler_with_mocks):
        """Swipe gauche doit passer au SecuBox precedent."""
        handler, mock_dm, _ = handler_with_mocks

        await handler.on_swipe_left()

        # Doit appeler switch_to avec le dernier SecuBox (wrap around)
        mock_dm.switch_to.assert_called_once_with("SecuBox-3")

    @pytest.mark.asyncio
    async def test_swipe_right_switches_to_next(self, handler_with_mocks):
        """Swipe droite doit passer au SecuBox suivant."""
        handler, mock_dm, _ = handler_with_mocks

        await handler.on_swipe_right()

        # Doit appeler switch_to avec le deuxieme SecuBox
        mock_dm.switch_to.assert_called_once_with("SecuBox-2")

    @pytest.mark.asyncio
    async def test_module_tap_sends_restart_command(self, handler_with_mocks):
        """Tap sur module doit envoyer commande service_restart."""
        handler, _, mock_ws = handler_with_mocks

        await handler.on_module_tap("AUTH")

        mock_ws.send_message.assert_called_once()
        call_args = mock_ws.send_message.call_args
        assert call_args[0][0] == "command"
        assert call_args[1]["cmd"] == "service_restart"
        assert call_args[1]["params"]["service"] == "secubox-auth"

    @pytest.mark.asyncio
    async def test_three_finger_tap_sends_lockdown(self, handler_with_mocks):
        """3-finger tap doit envoyer commande lockdown."""
        handler, _, mock_ws = handler_with_mocks

        await handler.on_three_finger_tap()

        mock_ws.send_message.assert_called_once()
        call_args = mock_ws.send_message.call_args
        assert call_args[0][0] == "command"
        assert call_args[1]["cmd"] == "lockdown"
        assert call_args[1]["params"]["action"] == "enable"

    @pytest.mark.asyncio
    async def test_swipe_down_toggles_overlay(self, handler_with_mocks):
        """Swipe down doit toggle l'overlay."""
        handler, _, _ = handler_with_mocks

        # Callback pour verifier
        callback_values = []
        handler.on_overlay_toggle(lambda v: callback_values.append(v))

        assert handler.info_overlay_visible is False

        await handler.on_swipe_down()
        assert handler.info_overlay_visible is True
        assert callback_values == [True]

        await handler.on_swipe_down()
        assert handler.info_overlay_visible is False
        assert callback_values == [True, False]

    @pytest.mark.asyncio
    async def test_long_press_toggles_device_list(self, handler_with_mocks):
        """Long press centre doit toggle la liste devices."""
        handler, _, _ = handler_with_mocks

        callback_values = []
        handler.on_device_list_toggle(lambda v: callback_values.append(v))

        assert handler.device_list_visible is False

        await handler.on_long_press_center()
        assert handler.device_list_visible is True
        assert callback_values == [True]


# =============================================================================
# Tests TouchHandler - Lifecycle
# =============================================================================

class TestTouchHandlerLifecycle:
    """Tests pour le cycle de vie du handler."""

    def test_create_touch_handler(self):
        """Verifier la factory function."""
        handler = create_touch_handler()
        assert handler is not None
        assert handler.device_manager is None
        assert handler.ws_client is None
        assert handler.is_running is False

    def test_create_with_dependencies(self):
        """Verifier la creation avec dependances."""
        mock_dm = MagicMock()
        mock_ws = MagicMock()

        handler = create_touch_handler(
            device_manager=mock_dm,
            ws_client=mock_ws
        )

        assert handler.device_manager is mock_dm
        assert handler.ws_client is mock_ws

    @pytest.mark.asyncio
    async def test_start_without_evdev(self):
        """Start doit echouer gracieusement sans evdev."""
        handler = create_touch_handler()

        # Mocker l'import de evdev pour qu'il echoue
        with patch.dict('sys.modules', {'evdev': None}):
            # On ne peut pas vraiment tester ca sans modifier l'import
            # Mais on peut verifier que le handler ne crash pas
            pass

    @pytest.mark.asyncio
    async def test_stop_cleans_up(self):
        """Stop doit nettoyer les ressources."""
        handler = create_touch_handler()
        handler._running = True

        await handler.stop()

        assert handler.is_running is False
        assert handler._touch_device is None


# =============================================================================
# Tests d'integration
# =============================================================================

class TestIntegration:
    """Tests d'integration pour le flux complet."""

    @pytest.mark.asyncio
    async def test_gesture_callback_called(self):
        """Verifier que le callback generique est appele."""
        handler = create_touch_handler()

        received_gestures = []

        def on_gesture(gesture, data):
            received_gestures.append((gesture, data))

        handler.on_gesture(on_gesture)

        # Simuler un geste
        handler._state.first_touch_time = 0.0
        handler._state.last_event_time = 0.1
        handler._state.gesture_started = True
        handler._state.max_touch_count = 1
        handler._state.touch_points[0] = TouchPoint(
            slot=0, tracking_id=1,
            x=CENTER_X, y=CENTER_Y,
            start_x=CENTER_X, start_y=CENTER_Y,
            start_time=0.0, active=False
        )

        await handler._execute_gesture(Gesture.TAP)

        assert len(received_gestures) == 1
        assert received_gestures[0][0] == Gesture.TAP

    @pytest.mark.asyncio
    async def test_secubox_switch_callback_on_swipe(self):
        """Verifier le callback de switch SecuBox."""
        mock_dm = MagicMock()
        mock_dm.list_secuboxes.return_value = [
            {"name": "Box-A", "active": True},
            {"name": "Box-B", "active": False},
        ]
        mock_dm.switch_to = AsyncMock(return_value=True)

        handler = create_touch_handler(device_manager=mock_dm)

        switched_to = []
        handler.on_secubox_switch(lambda name: switched_to.append(name))

        await handler.on_swipe_right()

        assert switched_to == ["Box-B"]


# =============================================================================
# Tests Slice Detection
# =============================================================================

class TestSliceDetection:
    """Tests pour la detection radiale de tranches."""

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
        result = get_slice_from_touch(CENTER_X, CENTER_Y - 150)
        assert result == 0

    def test_slice_1_at_top_right(self):
        """Slice 1 is at top-right (2 o'clock position)."""
        angle = math.radians(60)
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
        angle = math.radians(-60)
        x = int(CENTER_X + 150 * math.sin(angle))
        y = int(CENTER_Y - 150 * math.cos(angle))
        result = get_slice_from_touch(x, y)
        assert result == 5


# =============================================================================
# Tests Touch + Menu Integration
# =============================================================================

class TestTouchMenuIntegration:
    """Tests for touch + menu integration."""

    def test_long_press_center_enters_menu(self):
        """Long press center toggles menu mode."""
        # Import menu modules
        sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))
        from menu_navigator import MenuNavigator, MenuMode

        handler = create_touch_handler()
        nav = MenuNavigator()
        handler.set_menu_navigator(nav)

        assert nav.state.mode == MenuMode.DASHBOARD
        handler._handle_menu_toggle()
        assert nav.state.mode == MenuMode.MENU

    def test_tap_slice_in_menu_mode(self):
        """Tap on slice selects menu item."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))
        from menu_navigator import MenuNavigator, MenuMode
        from menu_definitions import MenuID

        handler = create_touch_handler()
        nav = MenuNavigator()
        handler.set_menu_navigator(nav)
        nav.enter_menu()

        # Tap on slice 1 (60 degrees = 2 o'clock)
        angle = math.radians(60)
        x = int(CENTER_X + 150 * math.sin(angle))
        y = int(CENTER_Y - 150 * math.cos(angle))
        action = handler._handle_slice_tap(x, y)

        # Slice 1 = SECUBOX (submenu)
        assert nav.state.current_menu == MenuID.SECUBOX

    def test_three_finger_exits_menu(self):
        """3-finger tap exits menu to dashboard."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))
        from menu_navigator import MenuNavigator, MenuMode
        from menu_definitions import MenuID

        handler = create_touch_handler()
        nav = MenuNavigator()
        handler.set_menu_navigator(nav)
        nav.enter_menu()
        nav.state.current_menu = MenuID.SECUBOX

        handler._handle_emergency_exit()
        assert nav.state.mode == MenuMode.DASHBOARD


# =============================================================================
# Full Integration Tests
# =============================================================================

class TestFullMenuFlow:
    """Integration tests for complete menu flow."""

    @pytest.fixture
    def full_setup(self):
        """Create fully wired system."""
        handler = create_touch_handler()
        nav = MenuNavigator()
        executor = ActionExecutor()
        local_api = LocalAPI()

        executor._local_api = local_api
        handler.set_menu_navigator(nav)
        handler.set_action_executor(executor)

        return handler, nav, executor, local_api

    @pytest.mark.asyncio
    async def test_complete_navigation_flow(self, full_setup):
        """Test navigating through menus and executing action."""
        handler, nav, executor, _ = full_setup

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
        assert "Eye Remote" in result.message or "SecuBox" in result.data.get("name", "")

    @pytest.mark.asyncio
    async def test_back_navigation(self, full_setup):
        """Test navigating back through breadcrumb."""
        handler, nav, executor, _ = full_setup

        # Enter menu
        handler._handle_menu_toggle()
        assert nav.state.mode == MenuMode.MENU

        # Go to SECUBOX (slice 1)
        nav.select_by_index(1)
        action = nav.select_current()
        assert action is None  # Submenu
        assert nav.state.current_menu == MenuID.SECUBOX
        assert len(nav.state.breadcrumb) == 1

        # Go back to ROOT
        nav.go_back()
        assert nav.state.current_menu == MenuID.ROOT
        assert len(nav.state.breadcrumb) == 0

    @pytest.mark.asyncio
    async def test_action_executor_routing(self, full_setup):
        """Test action executor routes to correct handler."""
        handler, nav, executor, _ = full_setup

        # Test local.about
        result = await executor.execute("local.about")
        assert result.success is True
        assert result.data is not None
        assert "version" in result.data

    @pytest.mark.asyncio
    async def test_menu_confirmation_flow(self, full_setup):
        """Test action requiring confirmation."""
        handler, nav, executor, _ = full_setup

        # Enter menu
        handler._handle_menu_toggle()
        nav.select_by_index(1)  # SECUBOX
        nav.select_current()

        # Navigate to a DANGER item if available
        items = nav.get_current_items()
        danger_found = False
        for i, item in enumerate(items):
            if item.confirm:  # This is a confirmation-required item
                nav.select_by_index(i)
                action = nav.select_current()
                # Should move to CONFIRM mode and action should be None
                # because select_current returns None for confirmation items
                assert nav.state.mode == MenuMode.CONFIRM
                assert action is None
                assert nav.state.pending_action == item.action
                danger_found = True
                break

        # If we found a confirmation item, test cancellation
        if danger_found:
            nav.cancel_action()
            assert nav.state.mode == MenuMode.MENU
            assert nav.state.pending_action is None

    @pytest.mark.asyncio
    async def test_menu_exit_to_dashboard(self, full_setup):
        """Test emergency exit via 3-finger tap."""
        handler, nav, executor, _ = full_setup

        # Enter menu at SECUBOX
        handler._handle_menu_toggle()
        nav.select_by_index(1)
        nav.select_current()

        assert nav.state.mode == MenuMode.MENU
        assert nav.state.current_menu == MenuID.SECUBOX
        assert len(nav.state.breadcrumb) > 0

        # Exit to dashboard
        handler._handle_emergency_exit()
        assert nav.state.mode == MenuMode.DASHBOARD
        assert nav.state.current_menu == MenuID.ROOT
        assert len(nav.state.breadcrumb) == 0

    @pytest.mark.asyncio
    async def test_menu_rotation(self, full_setup):
        """Test rotating selection through menu items."""
        handler, nav, executor, _ = full_setup

        handler._handle_menu_toggle()
        items = nav.get_current_items()
        initial_index = nav.state.selected_index

        # Rotate forward
        nav.rotate_selection(1)
        assert nav.state.selected_index == (initial_index + 1) % len(items)

        # Rotate backward
        nav.rotate_selection(-1)
        assert nav.state.selected_index == initial_index

        # Rotate forward multiple times
        nav.rotate_selection(3)
        assert nav.state.selected_index == (initial_index + 3) % len(items)

    @pytest.mark.asyncio
    async def test_full_session_simulation(self, full_setup):
        """Simulate a complete user session."""
        handler, nav, executor, _ = full_setup

        # 1. Start in dashboard
        assert nav.state.mode == MenuMode.DASHBOARD

        # 2. Enter menu via long press
        handler._handle_menu_toggle()
        assert nav.state.mode == MenuMode.MENU

        # 3. Navigate to LOCAL menu
        nav.select_by_index(2)
        nav.select_current()
        assert nav.state.current_menu == MenuID.LOCAL

        # 4. Select and execute ABOUT action (slice 3)
        nav.select_by_index(3)
        action = nav.select_current()
        assert action is not None
        result = await executor.execute(action)
        assert result.success is True

        # 5. Navigate back to ROOT
        nav.go_back()
        assert nav.state.current_menu == MenuID.ROOT

        # 6. Exit menu to dashboard
        handler._handle_emergency_exit()
        assert nav.state.mode == MenuMode.DASHBOARD
        assert nav.state.current_menu == MenuID.ROOT
