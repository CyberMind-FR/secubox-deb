"""
SecuBox Eye Remote - Touch Gesture Handler (HyperPixel2r Edition)
Gestionnaire de gestes tactiles utilisant la bibliotheque Pimoroni hyperpixel2r.

Architecture:
- Lecture des evenements tactiles via I2C direct (bus 11, addr 0x15)
- Detection des gestes: swipe, tap, long press
- Integration avec device_manager et menu_navigator pour les actions

Prerequis:
- pip install hyperpixel2r
- dtoverlay=hyperpixel2r:disable-touch dans /boot/config.txt

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from device_manager import DeviceManager
    from command_handler import WebSocketClient

log = logging.getLogger(__name__)


# =============================================================================
# Touch Enable/Disable Flag
# =============================================================================
TOUCH_ENABLED = True  # Now enabled with direct I2C polling

# =============================================================================
# HyperPixel 2r Configuration (I2C direct, no GPIO interrupt)
# =============================================================================
HYPERPIXEL_I2C_BUS = 11
HYPERPIXEL_I2C_ADDR = 0x15
HYPERPIXEL_INT_PIN = 27  # Not used - polling mode preferred

# =============================================================================
# Y-Stability Touch Filter (noise has erratic Y, real touch is stable)
# =============================================================================
Y_STABILITY_WINDOW = 0.15   # 150ms window for stability check
Y_MAX_RANGE = 50            # Maximum Y variation for stable touch
X_MAX_RANGE = 60            # Maximum X variation
MIN_STABLE_SAMPLES = 3      # Minimum samples for confirmation
TOUCH_DEBOUNCE = 0.08       # 80ms between touch confirmations
POLL_INTERVAL = 0.025       # 25ms polling interval (40Hz)

# =============================================================================
# Configuration de l'ecran HyperPixel 2.1 Round
# =============================================================================

# Dimensions de l'ecran circulaire (pixels)
DISPLAY_WIDTH = 480
DISPLAY_HEIGHT = 480
CENTER_X = DISPLAY_WIDTH // 2   # 240
CENTER_Y = DISPLAY_HEIGHT // 2  # 240

# Seuils de detection des gestes (pixels et millisecondes)
SWIPE_THRESHOLD = 50            # Distance minimale pour un swipe
LONG_PRESS_MS = 500             # Duree minimale pour un long press
TAP_MAX_MS = 300                # Duree maximale pour un tap simple
SWIPE_TOP_ZONE = 60             # Zone superieure pour swipe down (overlay)
SWIPE_BOTTOM_ZONE = 420         # Zone inferieure pour swipe up (menu)

# Zone centrale (pour long press / menu toggle)
CENTER_RADIUS = 80              # Zone centrale de 80px de rayon

# Rayons des anneaux de modules
MODULE_RINGS = {
    "AUTH": {"radius": 214, "color": "#C04E24", "inner": 207, "outer": 221},
    "WALL": {"radius": 201, "color": "#9A6010", "inner": 194, "outer": 207},
    "BOOT": {"radius": 188, "color": "#803018", "inner": 181, "outer": 194},
    "MIND": {"radius": 175, "color": "#3D35A0", "inner": 168, "outer": 181},
    "ROOT": {"radius": 162, "color": "#0A5840", "inner": 155, "outer": 168},
    "MESH": {"radius": 149, "color": "#104A88", "inner": 142, "outer": 155},
}

# =============================================================================
# Slice Detection for Radial Menu
# =============================================================================

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

    if distance < CENTER_ZONE_RADIUS:
        return None

    if distance > OUTER_ZONE_RADIUS:
        return None

    angle = math.degrees(math.atan2(dx, -dy))
    if angle < 0:
        angle += 360

    slice_index = int((angle + 30) % 360 // 60)
    return slice_index


# =============================================================================
# Types de gestes detectes
# =============================================================================

class Gesture(Enum):
    """Types de gestes tactiles reconnus."""
    NONE = auto()
    TAP = auto()
    LONG_PRESS = auto()
    SWIPE_LEFT = auto()
    SWIPE_RIGHT = auto()
    SWIPE_UP = auto()
    SWIPE_DOWN = auto()


# =============================================================================
# Etat du geste en cours
# =============================================================================

@dataclass
class TouchState:
    """Etat d'un touch en cours."""
    touch_id: int = 0
    start_x: int = 0
    start_y: int = 0
    current_x: int = 0
    current_y: int = 0
    start_time: float = 0.0
    active: bool = False


# =============================================================================
# Gestionnaire de gestes tactiles (Pimoroni Edition)
# =============================================================================

@dataclass
class TouchHandler:
    """
    Gestionnaire de gestes tactiles pour HyperPixel 2.1 Round.

    Utilise la bibliotheque Pimoroni hyperpixel2r pour l'acces I2C direct.

    Attributes:
        device_manager: Gestionnaire des connexions SecuBox
        ws_client: Client WebSocket pour les commandes
    """

    device_manager: Optional[Any] = None
    ws_client: Optional[Any] = None

    # Touch device (Pimoroni)
    _touch: Optional[Any] = field(default=None, repr=False)

    # Etat du touch
    _state: TouchState = field(default_factory=TouchState, repr=False)

    # Etat de l'UI
    _info_overlay_visible: bool = field(default=False, repr=False)
    _device_list_visible: bool = field(default=False, repr=False)

    # Controle
    _running: bool = field(default=False, repr=False)
    _event_loop: Optional[asyncio.AbstractEventLoop] = field(default=None, repr=False)

    # Callbacks externes
    _on_overlay_toggle: Optional[Callable[[bool], None]] = field(default=None, repr=False)
    _on_device_list_toggle: Optional[Callable[[bool], None]] = field(default=None, repr=False)
    _on_secubox_switch: Optional[Callable[[str], None]] = field(default=None, repr=False)
    _on_gesture: Optional[Callable[[Gesture, dict], None]] = field(default=None, repr=False)

    # Menu integration
    _menu_navigator: Optional[Any] = field(default=None, repr=False)
    _action_executor: Optional[Any] = field(default=None, repr=False)
    _on_menu_render: Optional[Callable[[Any], None]] = field(default=None, repr=False)

    # Long press detection
    _long_press_task: Optional[asyncio.Task] = field(default=None, repr=False)
    _long_press_triggered: bool = field(default=False, repr=False)

    # ==========================================================================
    # Initialisation
    # ==========================================================================

    async def start(self) -> bool:
        """
        Demarrer le gestionnaire de gestes.

        Utilise I2C polling direct avec filtre Y-stability (plus fiable
        que les interrupts GPIO qui captent du bruit).
        """
        if not TOUCH_ENABLED:
            log.warning("Touch disabled via TOUCH_ENABLED flag")
            return False

        try:
            import smbus2
            self._i2c_bus = smbus2.SMBus(HYPERPIXEL_I2C_BUS)
        except ImportError:
            log.error("Module smbus2 non installe: pip install smbus2")
            return await self._start_evdev_fallback()
        except Exception as e:
            log.error("Erreur ouverture I2C bus %d: %s", HYPERPIXEL_I2C_BUS, e)
            return await self._start_evdev_fallback()

        # Initialize Y-stability filter state
        self._touch_samples = []  # [(x, y, timestamp), ...]
        self._last_confirm_time = 0
        self._last_confirmed_pos = None
        self._touch_active = False
        self._no_touch_count = 0

        self._running = True
        self._event_loop = asyncio.get_event_loop()

        # Start polling task
        asyncio.create_task(self._i2c_polling_loop())

        log.info("TouchHandler (I2C polling + Y-stability) demarre - bus=%d addr=0x%02X",
                 HYPERPIXEL_I2C_BUS, HYPERPIXEL_I2C_ADDR)
        return True

    async def _i2c_polling_loop(self):
        """
        Boucle de polling I2C avec filtre Y-stability.

        Le bruit du touchpad HyperPixel2r se caracterise par des sauts
        erratiques sur l'axe Y. Les vrais touches sont stables en Y.
        """
        import struct

        while self._running:
            try:
                # Read touch count from register 0x02
                count = self._i2c_bus.read_byte_data(HYPERPIXEL_I2C_ADDR, 0x02)

                if count > 0:
                    self._no_touch_count = 0

                    # Read touch data (6 bytes) from register 0x03
                    data = self._i2c_bus.read_i2c_block_data(HYPERPIXEL_I2C_ADDR, 0x03, 6)

                    # Parse touch event and coordinates
                    touch_event = data[0] & 0xf0
                    data[0] &= 0x0f
                    data[2] &= 0x0f
                    tx, ty, p1, p2 = struct.unpack(">HHBB", bytes(data))
                    now = time.time()

                    # Check for release event (0x40)
                    if touch_event & 0x40:
                        if self._touch_active:
                            log.debug("Touch RELEASE at (%d, %d)", tx, ty)
                            self._on_touch_event(0, tx, ty, False)
                            self._touch_active = False
                            self._touch_samples.clear()
                            self._last_confirmed_pos = None
                        continue

                    # Add sample for stability checking
                    self._touch_samples.append((tx, ty, now))

                    # Remove old samples outside window
                    self._touch_samples = [
                        s for s in self._touch_samples
                        if now - s[2] < Y_STABILITY_WINDOW
                    ]

                    # Check stability if enough samples
                    if len(self._touch_samples) >= MIN_STABLE_SAMPLES:
                        y_values = [s[1] for s in self._touch_samples]
                        x_values = [s[0] for s in self._touch_samples]

                        y_range = max(y_values) - min(y_values)
                        x_range = max(x_values) - min(x_values)

                        # Stable if Y and X don't jump around
                        if y_range < Y_MAX_RANGE and x_range < X_MAX_RANGE:
                            avg_x = sum(x_values) // len(x_values)
                            avg_y = sum(y_values) // len(y_values)

                            # Debounce check
                            if now - self._last_confirm_time >= TOUCH_DEBOUNCE:
                                # Check if position changed significantly
                                if (self._last_confirmed_pos is None or
                                    abs(avg_x - self._last_confirmed_pos[0]) > 25 or
                                    abs(avg_y - self._last_confirmed_pos[1]) > 25):

                                    log.debug("Touch CONFIRMED at (%d, %d) y_range=%d",
                                              avg_x, avg_y, y_range)

                                    if not self._touch_active:
                                        # New touch - trigger start
                                        self._on_touch_event(0, avg_x, avg_y, True)

                                    self._last_confirmed_pos = (avg_x, avg_y)
                                    self._last_confirm_time = now
                                    self._touch_active = True
                else:
                    # No touch detected
                    self._no_touch_count += 1
                    if self._no_touch_count > 5 and self._touch_active:
                        log.debug("Touch RELEASE (timeout)")
                        if self._last_confirmed_pos:
                            self._on_touch_event(0, self._last_confirmed_pos[0],
                                                 self._last_confirmed_pos[1], False)
                        self._touch_active = False
                        self._touch_samples.clear()
                        self._last_confirmed_pos = None

            except Exception as e:
                if "Remote I/O error" not in str(e):
                    log.warning("I2C read error: %s", e)

            await asyncio.sleep(POLL_INTERVAL)

    async def _start_evdev_fallback(self) -> bool:
        """Fallback vers evdev si Pimoroni echoue."""
        try:
            import evdev
        except ImportError:
            log.error("Ni hyperpixel2r ni evdev disponible - touch desactive")
            return False

        # Find touch device
        from pathlib import Path
        input_dir = Path("/dev/input")

        for event_path in sorted(input_dir.glob("event*")):
            try:
                device = evdev.InputDevice(str(event_path))
                caps = device.capabilities()

                if evdev.ecodes.EV_ABS in caps:
                    abs_caps = dict(caps[evdev.ecodes.EV_ABS])
                    if evdev.ecodes.ABS_MT_SLOT in abs_caps:
                        name = device.name.lower()
                        if any(x in name for x in ['goodix', 'ft5', 'hyperpixel', 'touch']):
                            self._touch = device
                            self._running = True
                            self._event_loop = asyncio.get_event_loop()

                            # Start evdev event loop
                            asyncio.create_task(self._evdev_event_loop())

                            log.info("TouchHandler (evdev fallback) demarre: %s", device.name)
                            return True
                device.close()
            except (OSError, PermissionError):
                continue

        log.warning("Aucun peripherique tactile trouve")
        return False

    async def _evdev_event_loop(self):
        """Boucle evdev de fallback."""
        import evdev

        current_slot = 0
        tracking_id = -1

        try:
            async for event in self._touch.async_read_loop():
                if not self._running:
                    break

                if event.type == evdev.ecodes.EV_ABS:
                    if event.code == evdev.ecodes.ABS_MT_SLOT:
                        current_slot = event.value
                    elif event.code == evdev.ecodes.ABS_MT_TRACKING_ID:
                        if event.value >= 0:
                            # Touch start
                            tracking_id = event.value
                            self._state.touch_id = current_slot
                            self._state.start_time = time.time()
                            self._state.active = True
                        else:
                            # Touch end
                            if self._state.active:
                                self._on_touch_event(
                                    self._state.touch_id,
                                    self._state.current_x,
                                    self._state.current_y,
                                    False
                                )
                            self._state.active = False
                    elif event.code == evdev.ecodes.ABS_MT_POSITION_X:
                        if self._state.start_x == 0:
                            self._state.start_x = event.value
                        self._state.current_x = event.value
                        if self._state.active and self._state.start_time > 0:
                            # First position - trigger touch start
                            self._on_touch_event(
                                self._state.touch_id,
                                event.value,
                                self._state.current_y,
                                True
                            )
                    elif event.code == evdev.ecodes.ABS_MT_POSITION_Y:
                        if self._state.start_y == 0:
                            self._state.start_y = event.value
                        self._state.current_y = event.value

        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error("Erreur evdev: %s", e)

    async def stop(self):
        """Arreter le gestionnaire de gestes."""
        self._running = False

        if self._long_press_task:
            self._long_press_task.cancel()
            self._long_press_task = None

        if self._touch:
            try:
                # Pimoroni Touch doesn't have explicit close
                if hasattr(self._touch, 'close'):
                    self._touch.close()
            except Exception:
                pass
            self._touch = None

        log.info("TouchHandler arrete")

    # ==========================================================================
    # Touch Event Handler
    # ==========================================================================

    def _on_touch_event(self, touch_id: int, x: int, y: int, state: bool):
        """
        Callback appele par Pimoroni pour chaque evenement touch.

        Args:
            touch_id: ID du point de contact (0 ou 1)
            x: Position X (0-479)
            y: Position Y (0-479)
            state: True=pressed, False=released
        """
        now = time.time()

        if state:
            # Touch pressed
            log.debug("Touch START id=%d at (%d, %d)", touch_id, x, y)

            self._state = TouchState(
                touch_id=touch_id,
                start_x=x,
                start_y=y,
                current_x=x,
                current_y=y,
                start_time=now,
                active=True
            )
            self._long_press_triggered = False

            # Start long press timer
            if self._event_loop:
                self._long_press_task = self._event_loop.create_task(
                    self._check_long_press()
                )

        else:
            # Touch released
            if not self._state.active:
                return

            log.debug("Touch END id=%d at (%d, %d)", touch_id, x, y)

            # Cancel long press timer
            if self._long_press_task:
                self._long_press_task.cancel()
                self._long_press_task = None

            # Update final position
            self._state.current_x = x
            self._state.current_y = y
            self._state.active = False

            # Don't process gesture if long press was triggered
            if self._long_press_triggered:
                return

            # Detect and execute gesture
            gesture = self._detect_gesture(now)
            if gesture != Gesture.NONE and self._event_loop:
                self._event_loop.create_task(self._execute_gesture(gesture))

    async def _check_long_press(self):
        """Verifier si le touch devient un long press."""
        try:
            await asyncio.sleep(LONG_PRESS_MS / 1000.0)

            if self._state.active and not self._long_press_triggered:
                # Check if still near start position (not a swipe)
                dx = abs(self._state.current_x - self._state.start_x)
                dy = abs(self._state.current_y - self._state.start_y)

                if dx < SWIPE_THRESHOLD / 2 and dy < SWIPE_THRESHOLD / 2:
                    # Check if in center zone
                    dist = math.sqrt(
                        (self._state.current_x - CENTER_X) ** 2 +
                        (self._state.current_y - CENTER_Y) ** 2
                    )

                    if dist < CENTER_RADIUS:
                        self._long_press_triggered = True
                        log.info("Geste detecte: LONG_PRESS at center")
                        await self._execute_gesture(Gesture.LONG_PRESS)

        except asyncio.CancelledError:
            pass

    def _detect_gesture(self, end_time: float) -> Gesture:
        """
        Analyser le touch et determiner le type de geste.

        Args:
            end_time: Timestamp de fin du touch

        Returns:
            Type de geste detecte
        """
        duration_ms = (end_time - self._state.start_time) * 1000
        dx = self._state.current_x - self._state.start_x
        dy = self._state.current_y - self._state.start_y
        distance = math.sqrt(dx * dx + dy * dy)

        log.debug(
            "Analyse geste: duration=%.0fms dx=%d dy=%d dist=%.0f",
            duration_ms, dx, dy, distance
        )

        # Swipe horizontal
        if abs(dx) > SWIPE_THRESHOLD and abs(dx) > abs(dy) * 1.5:
            if dx < 0:
                log.info("Geste detecte: SWIPE_LEFT")
                return Gesture.SWIPE_LEFT
            else:
                log.info("Geste detecte: SWIPE_RIGHT")
                return Gesture.SWIPE_RIGHT

        # Swipe down from top
        if (dy > SWIPE_THRESHOLD and
            self._state.start_y < SWIPE_TOP_ZONE and
            abs(dy) > abs(dx) * 1.5):
            log.info("Geste detecte: SWIPE_DOWN")
            return Gesture.SWIPE_DOWN

        # Swipe up from bottom
        if (dy < -SWIPE_THRESHOLD and
            self._state.start_y > SWIPE_BOTTOM_ZONE and
            abs(dy) > abs(dx) * 1.5):
            log.info("Geste detecte: SWIPE_UP")
            return Gesture.SWIPE_UP

        # Tap (short touch with minimal movement)
        if duration_ms < TAP_MAX_MS and distance < SWIPE_THRESHOLD / 2:
            log.info("Geste detecte: TAP at (%d, %d)",
                     self._state.current_x, self._state.current_y)
            return Gesture.TAP

        log.debug("Geste non reconnu")
        return Gesture.NONE

    # ==========================================================================
    # Callbacks pour l'integration UI
    # ==========================================================================

    def on_overlay_toggle(self, callback: Callable[[bool], None]):
        """Callback quand l'overlay info est toggle."""
        self._on_overlay_toggle = callback

    def on_device_list_toggle(self, callback: Callable[[bool], None]):
        """Callback quand la liste des devices est toggle."""
        self._on_device_list_toggle = callback

    def on_secubox_switch(self, callback: Callable[[str], None]):
        """Callback quand on change de SecuBox."""
        self._on_secubox_switch = callback

    def on_gesture(self, callback: Callable[[Gesture, dict], None]):
        """Callback generique pour tous les gestes."""
        self._on_gesture = callback

    def set_menu_navigator(self, navigator: Any):
        """Definir le navigateur de menu."""
        self._menu_navigator = navigator

    def set_action_executor(self, executor: Any):
        """Definir l'executeur d'actions."""
        self._action_executor = executor

    def on_menu_render(self, callback: Callable[[Any], None]):
        """Callback pour notifier que le menu doit etre rendu."""
        self._on_menu_render = callback

    # ==========================================================================
    # Execution des gestes
    # ==========================================================================

    async def _execute_gesture(self, gesture: Gesture):
        """
        Executer l'action correspondant au geste detecte.

        Args:
            gesture: Type de geste detecte
        """
        # Callback generique
        if self._on_gesture:
            try:
                self._on_gesture(gesture, {
                    "x": self._state.current_x,
                    "y": self._state.current_y,
                })
            except Exception as e:
                log.warning("Erreur callback on_gesture: %s", e)

        # Verifier si on est en mode menu
        in_menu_mode = False
        if self._menu_navigator:
            try:
                from menu_navigator import MenuMode
                in_menu_mode = self._menu_navigator.state.mode == MenuMode.MENU
            except ImportError:
                pass

        # Long press centre: toggle menu
        if gesture == Gesture.LONG_PRESS:
            await self._on_long_press_center()
            return

        # Swipe up from bottom: enter menu (alternative)
        if gesture == Gesture.SWIPE_UP:
            log.info("SWIPE_UP - entering menu")
            await self._on_long_press_center()
            return

        # Si en mode menu
        if in_menu_mode:
            if gesture == Gesture.TAP:
                self._handle_slice_tap(self._state.current_x, self._state.current_y)

            elif gesture == Gesture.SWIPE_LEFT:
                if self._menu_navigator:
                    current = self._menu_navigator.state.selected_index
                    self._menu_navigator.state.selected_index = (current - 1) % 6
                    if self._on_menu_render:
                        self._on_menu_render(self._menu_navigator.state)

            elif gesture == Gesture.SWIPE_RIGHT:
                if self._menu_navigator:
                    current = self._menu_navigator.state.selected_index
                    self._menu_navigator.state.selected_index = (current + 1) % 6
                    if self._on_menu_render:
                        self._on_menu_render(self._menu_navigator.state)

        else:
            # Mode dashboard
            if gesture == Gesture.SWIPE_LEFT:
                await self._on_swipe_left()

            elif gesture == Gesture.SWIPE_RIGHT:
                await self._on_swipe_right()

            elif gesture == Gesture.TAP:
                module = self._detect_module_from_position(
                    self._state.current_x,
                    self._state.current_y
                )
                if module:
                    await self._on_module_tap(module)

            elif gesture == Gesture.SWIPE_DOWN:
                await self._on_swipe_down()

    def _detect_module_from_position(self, x: int, y: int) -> Optional[str]:
        """Determiner le module touche en fonction de la position."""
        dist = math.sqrt((x - CENTER_X) ** 2 + (y - CENTER_Y) ** 2)

        for module_name, ring in MODULE_RINGS.items():
            if ring["inner"] <= dist <= ring["outer"]:
                log.debug("Module detecte: %s (dist=%.0f)", module_name, dist)
                return module_name

        return None

    # ==========================================================================
    # Actions de gestes
    # ==========================================================================

    async def _on_swipe_left(self):
        """Swipe gauche: SecuBox precedent."""
        if not self.device_manager:
            return

        boxes = self.device_manager.list_secuboxes()
        if len(boxes) < 2:
            return

        current_idx = next(
            (i for i, b in enumerate(boxes) if b.get("active")),
            0
        )
        prev_idx = (current_idx - 1) % len(boxes)
        prev_name = boxes[prev_idx]["name"]

        log.info("Switch vers SecuBox: %s", prev_name)
        try:
            success = await self.device_manager.switch_to(prev_name)
            if success and self._on_secubox_switch:
                self._on_secubox_switch(prev_name)
        except Exception as e:
            log.error("Erreur switch: %s", e)

    async def _on_swipe_right(self):
        """Swipe droite: SecuBox suivant."""
        if not self.device_manager:
            return

        boxes = self.device_manager.list_secuboxes()
        if len(boxes) < 2:
            return

        current_idx = next(
            (i for i, b in enumerate(boxes) if b.get("active")),
            0
        )
        next_idx = (current_idx + 1) % len(boxes)
        next_name = boxes[next_idx]["name"]

        log.info("Switch vers SecuBox: %s", next_name)
        try:
            success = await self.device_manager.switch_to(next_name)
            if success and self._on_secubox_switch:
                self._on_secubox_switch(next_name)
        except Exception as e:
            log.error("Erreur switch: %s", e)

    async def _on_module_tap(self, module: str):
        """Tap sur anneau module: redemarrer le service."""
        log.info("Tap sur module: %s", module)

        if not self.ws_client:
            return

        service_name = f"secubox-{module.lower()}"
        try:
            await self.ws_client.send_message(
                "command",
                cmd="service_restart",
                params={"service": service_name}
            )
        except Exception as e:
            log.error("Erreur commande: %s", e)

    async def _on_swipe_down(self):
        """Swipe down: toggle overlay info."""
        self._info_overlay_visible = not self._info_overlay_visible
        log.info("Toggle overlay: %s",
                 "visible" if self._info_overlay_visible else "cache")

        if self._on_overlay_toggle:
            try:
                self._on_overlay_toggle(self._info_overlay_visible)
            except Exception as e:
                log.warning("Erreur callback: %s", e)

    async def _on_long_press_center(self):
        """Long press centre: toggle menu."""
        if self._menu_navigator:
            self._handle_menu_toggle()
            return

        # Fallback: device list
        self._device_list_visible = not self._device_list_visible
        log.info("Toggle device list: %s",
                 "visible" if self._device_list_visible else "cache")

        if self._on_device_list_toggle:
            try:
                self._on_device_list_toggle(self._device_list_visible)
            except Exception as e:
                log.warning("Erreur callback: %s", e)

    # ==========================================================================
    # Menu Integration
    # ==========================================================================

    def _handle_menu_toggle(self):
        """Toggle entre mode menu et dashboard."""
        if not self._menu_navigator:
            return

        from menu_navigator import MenuMode

        if self._menu_navigator.state.mode == MenuMode.DASHBOARD:
            log.info("Entree en mode menu")
            self._menu_navigator.enter_menu()
        else:
            log.info("Sortie vers dashboard")
            self._menu_navigator.exit_to_dashboard()

        if self._on_menu_render:
            try:
                self._on_menu_render(self._menu_navigator.state)
            except Exception as e:
                log.warning("Erreur callback: %s", e)

    def _handle_slice_tap(self, x: int, y: int) -> Optional[str]:
        """Gerer un tap sur une tranche du menu radial."""
        if not self._menu_navigator:
            return None

        slice_index = get_slice_from_touch(x, y)
        if slice_index is None:
            # Tap in center - go back
            if self._menu_navigator.state.breadcrumb:
                self._menu_navigator.go_back()
            else:
                self._menu_navigator.exit_to_dashboard()

            if self._on_menu_render:
                self._on_menu_render(self._menu_navigator.state)
            return None

        log.info("Tap sur tranche menu: %d", slice_index)

        self._menu_navigator.state.selected_index = slice_index
        action = self._menu_navigator.select_current()

        if action and self._action_executor:
            try:
                asyncio.create_task(self._action_executor.execute(action))
            except Exception as e:
                log.error("Erreur execution: %s", e)

        if self._on_menu_render:
            try:
                self._on_menu_render(self._menu_navigator.state)
            except Exception as e:
                log.warning("Erreur callback: %s", e)

        return action

    # ==========================================================================
    # Proprietes
    # ==========================================================================

    @property
    def is_running(self) -> bool:
        """Verifier si le handler est actif."""
        return self._running

    @property
    def info_overlay_visible(self) -> bool:
        """Etat de l'overlay info."""
        return self._info_overlay_visible

    @property
    def device_list_visible(self) -> bool:
        """Etat de la liste des devices."""
        return self._device_list_visible

    @property
    def touch_device_name(self) -> Optional[str]:
        """Nom du peripherique tactile."""
        if self._touch:
            if hasattr(self._touch, 'name'):
                return self._touch.name
            return "HyperPixel2r I2C Touch"
        return None


# =============================================================================
# Factory function
# =============================================================================

def create_touch_handler(
    device_manager: Optional[Any] = None,
    ws_client: Optional[Any] = None
) -> TouchHandler:
    """
    Creer un gestionnaire de gestes tactiles.

    Args:
        device_manager: Gestionnaire des connexions SecuBox
        ws_client: Client WebSocket pour les commandes

    Returns:
        Instance de TouchHandler configuree
    """
    return TouchHandler(
        device_manager=device_manager,
        ws_client=ws_client
    )


# =============================================================================
# Test standalone
# =============================================================================

async def main():
    """Test du TouchHandler avec Pimoroni."""
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    log.info("Test TouchHandler (Pimoroni hyperpixel2r)")

    handler = create_touch_handler()

    def on_gesture_demo(gesture: Gesture, data: dict):
        print(f">>> Geste: {gesture.name} - {data}")

    handler.on_gesture(on_gesture_demo)

    success = await handler.start()
    if not success:
        log.error("Echec demarrage touch handler")
        sys.exit(1)

    log.info("TouchHandler actif: %s", handler.touch_device_name)
    log.info("Testez les gestes. Ctrl+C pour quitter.")

    try:
        while handler.is_running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        log.info("Arret")
    finally:
        await handler.stop()


if __name__ == "__main__":
    asyncio.run(main())
