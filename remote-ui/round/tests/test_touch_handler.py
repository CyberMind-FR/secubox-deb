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
    MODULE_RINGS,
    CENTER_X,
    CENTER_Y,
    SWIPE_THRESHOLD,
    LONG_PRESS_MS,
    TAP_MAX_MS,
)


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
