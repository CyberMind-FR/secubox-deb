#!/usr/bin/env python3
"""
SecuBox Eye Remote - Gadget Mode Gesture Handler

Detects touch gestures for switching USB gadget modes.
Integrates with the display manager for visual feedback.

Gestures:
- Long press on gadget indicator: Open mode selector
- Swipe left/right on mode selector: Change mode
- Tap on mode: Select mode
- Tap outside: Close selector

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

from __future__ import annotations

import math
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Callable, Any
from PIL import ImageDraw

# Import gadget control
try:
    from ..api.gadget_switcher import switch_mode, get_available_modes, get_current_mode
    HAS_GADGET_CONTROL = True
except ImportError:
    HAS_GADGET_CONTROL = False


WIDTH = HEIGHT = 480
CENTER = 240

# Mode display info
MODE_INFO = {
    'none': {
        'icon': '○',
        'name': 'Disabled',
        'color': (80, 80, 80),
        'description': 'USB gadget off',
    },
    'ecm': {
        'icon': '🌐',
        'name': 'Network',
        'color': (0, 180, 255),
        'description': 'Ethernet over USB',
    },
    'acm': {
        'icon': '📟',
        'name': 'Serial',
        'color': (255, 200, 0),
        'description': 'Serial console',
    },
    'mass_storage': {
        'icon': '💾',
        'name': 'Storage',
        'color': (0, 255, 120),
        'description': 'USB drive mode',
    },
    'composite': {
        'icon': '🔗',
        'name': 'Composite',
        'color': (200, 100, 255),
        'description': 'All modes combined',
    },
}


class GestureState(Enum):
    """Gesture handler state."""
    IDLE = "idle"
    LONG_PRESS_PENDING = "long_press_pending"
    MODE_SELECTOR_OPEN = "mode_selector_open"
    SWITCHING = "switching"


@dataclass
class TouchPoint:
    """A touch event point."""
    x: int
    y: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class GestureResult:
    """Result of gesture processing."""
    handled: bool = False
    mode_changed: bool = False
    new_mode: Optional[str] = None
    open_selector: bool = False
    close_selector: bool = False


class GadgetGestureHandler:
    """Handles touch gestures for gadget mode control."""

    # Gesture thresholds
    LONG_PRESS_TIME = 0.8  # seconds
    SWIPE_THRESHOLD = 50   # pixels
    TAP_THRESHOLD = 20     # pixels

    # Indicator position (bottom right corner)
    INDICATOR_X = WIDTH - 40
    INDICATOR_Y = HEIGHT - 40
    INDICATOR_RADIUS = 35

    # Mode selector dimensions
    SELECTOR_CENTER_Y = CENTER
    SELECTOR_RADIUS = 150
    SELECTOR_ITEM_RADIUS = 40

    def __init__(self):
        self._state = GestureState.IDLE
        self._touch_start: Optional[TouchPoint] = None
        self._last_touch: Optional[TouchPoint] = None
        self._selected_mode_index = 0
        self._available_modes: List[str] = []
        self._current_mode = "none"
        self._animation_phase = 0
        self._switching_progress = 0.0
        self._on_mode_change: Optional[Callable[[str], None]] = None

        # Load available modes
        if HAS_GADGET_CONTROL:
            self._available_modes = get_available_modes()
            self._current_mode = get_current_mode()
        else:
            self._available_modes = ["none", "ecm", "acm", "mass_storage", "composite"]

    def set_mode_change_callback(self, callback: Callable[[str], None]):
        """Set callback for mode changes."""
        self._on_mode_change = callback

    def _point_in_indicator(self, x: int, y: int) -> bool:
        """Check if point is within indicator area."""
        dx = x - self.INDICATOR_X
        dy = y - self.INDICATOR_Y
        return (dx * dx + dy * dy) <= (self.INDICATOR_RADIUS * self.INDICATOR_RADIUS)

    def _point_in_selector(self, x: int, y: int) -> Optional[int]:
        """Check if point is on a mode item, return item index or None."""
        if not self._available_modes:
            return None

        n_modes = len(self._available_modes)
        for i in range(n_modes):
            angle = (i / n_modes) * 2 * math.pi - math.pi / 2
            item_x = CENTER + self.SELECTOR_RADIUS * math.cos(angle)
            item_y = self.SELECTOR_CENTER_Y + self.SELECTOR_RADIUS * math.sin(angle)

            dx = x - item_x
            dy = y - item_y
            if (dx * dx + dy * dy) <= (self.SELECTOR_ITEM_RADIUS * self.SELECTOR_ITEM_RADIUS):
                return i

        return None

    def _get_swipe_direction(self, start: TouchPoint, end: TouchPoint) -> Optional[str]:
        """Determine swipe direction."""
        dx = end.x - start.x
        dy = end.y - start.y

        if abs(dx) < self.SWIPE_THRESHOLD and abs(dy) < self.SWIPE_THRESHOLD:
            return None

        if abs(dx) > abs(dy):
            return "right" if dx > 0 else "left"
        else:
            return "down" if dy > 0 else "up"

    def handle_touch_start(self, x: int, y: int) -> GestureResult:
        """Handle touch start event."""
        self._touch_start = TouchPoint(x, y)
        self._last_touch = self._touch_start

        if self._state == GestureState.IDLE:
            if self._point_in_indicator(x, y):
                self._state = GestureState.LONG_PRESS_PENDING
                return GestureResult(handled=True)

        elif self._state == GestureState.MODE_SELECTOR_OPEN:
            # Check if tapped on a mode item
            mode_index = self._point_in_selector(x, y)
            if mode_index is not None:
                self._selected_mode_index = mode_index
                return GestureResult(handled=True)

        return GestureResult(handled=False)

    def handle_touch_move(self, x: int, y: int) -> GestureResult:
        """Handle touch move event."""
        if not self._touch_start:
            return GestureResult(handled=False)

        self._last_touch = TouchPoint(x, y)

        if self._state == GestureState.LONG_PRESS_PENDING:
            # Cancel long press if moved too far
            dx = x - self._touch_start.x
            dy = y - self._touch_start.y
            if (dx * dx + dy * dy) > (self.TAP_THRESHOLD * self.TAP_THRESHOLD):
                self._state = GestureState.IDLE
                return GestureResult(handled=False)

        elif self._state == GestureState.MODE_SELECTOR_OPEN:
            # Update selected item based on angle from center
            dx = x - CENTER
            dy = y - self.SELECTOR_CENTER_Y
            if dx != 0 or dy != 0:
                angle = math.atan2(dy, dx) + math.pi / 2
                if angle < 0:
                    angle += 2 * math.pi
                n_modes = len(self._available_modes)
                self._selected_mode_index = int((angle / (2 * math.pi)) * n_modes) % n_modes

            return GestureResult(handled=True)

        return GestureResult(handled=False)

    def handle_touch_end(self, x: int, y: int) -> GestureResult:
        """Handle touch end event."""
        result = GestureResult(handled=False)

        if not self._touch_start:
            return result

        end_point = TouchPoint(x, y)
        duration = end_point.timestamp - self._touch_start.timestamp
        swipe = self._get_swipe_direction(self._touch_start, end_point)

        if self._state == GestureState.LONG_PRESS_PENDING:
            if duration >= self.LONG_PRESS_TIME:
                # Long press completed - open selector
                self._state = GestureState.MODE_SELECTOR_OPEN
                self._selected_mode_index = self._available_modes.index(self._current_mode) \
                    if self._current_mode in self._available_modes else 0
                result = GestureResult(handled=True, open_selector=True)
            else:
                # Short tap on indicator - quick toggle
                self._state = GestureState.IDLE
                result = GestureResult(handled=True)

        elif self._state == GestureState.MODE_SELECTOR_OPEN:
            mode_index = self._point_in_selector(x, y)

            if mode_index is not None:
                # Tapped on a mode - select it
                new_mode = self._available_modes[mode_index]
                if new_mode != self._current_mode:
                    self._switch_to_mode(new_mode)
                    result = GestureResult(
                        handled=True,
                        mode_changed=True,
                        new_mode=new_mode,
                        close_selector=True
                    )
                else:
                    result = GestureResult(handled=True, close_selector=True)
                self._state = GestureState.IDLE

            elif swipe == "left" or swipe == "right":
                # Swipe to change selection
                delta = 1 if swipe == "right" else -1
                self._selected_mode_index = (self._selected_mode_index + delta) % len(self._available_modes)
                result = GestureResult(handled=True)

            else:
                # Tap outside - close selector
                self._state = GestureState.IDLE
                result = GestureResult(handled=True, close_selector=True)

        self._touch_start = None
        self._last_touch = None

        return result

    def update(self) -> bool:
        """Update animation state. Returns True if display needs refresh."""
        self._animation_phase += 0.1

        # Check for long press timeout
        if self._state == GestureState.LONG_PRESS_PENDING and self._touch_start:
            if time.time() - self._touch_start.timestamp >= self.LONG_PRESS_TIME:
                self._state = GestureState.MODE_SELECTOR_OPEN
                self._selected_mode_index = self._available_modes.index(self._current_mode) \
                    if self._current_mode in self._available_modes else 0
                return True

        # Update switching progress
        if self._state == GestureState.SWITCHING:
            self._switching_progress += 0.1
            if self._switching_progress >= 1.0:
                self._state = GestureState.IDLE
                self._switching_progress = 0.0
            return True

        return self._state != GestureState.IDLE

    def _switch_to_mode(self, mode: str):
        """Switch to specified mode."""
        self._state = GestureState.SWITCHING
        self._switching_progress = 0.0

        if HAS_GADGET_CONTROL:
            result = switch_mode(mode)
            if result.result.value == "success":
                self._current_mode = mode

        if self._on_mode_change:
            self._on_mode_change(mode)

    @property
    def is_selector_open(self) -> bool:
        """Check if mode selector is open."""
        return self._state == GestureState.MODE_SELECTOR_OPEN

    @property
    def is_switching(self) -> bool:
        """Check if currently switching modes."""
        return self._state == GestureState.SWITCHING

    def render_indicator(self, draw: ImageDraw.ImageDraw):
        """Render the gadget indicator (corner badge)."""
        mode_info = MODE_INFO.get(self._current_mode, MODE_INFO['none'])
        color = mode_info['color']

        # Pulsing effect
        pulse = (math.sin(self._animation_phase) + 1) / 2
        size = int(8 + pulse * 4)

        # Draw indicator dot
        x, y = self.INDICATOR_X, self.INDICATOR_Y
        draw.ellipse([x - size, y - size, x + size, y + size], fill=color)

        # Mode letter
        mode_letter = self._current_mode[0].upper() if self._current_mode != "none" else "○"
        draw.text((x + size + 5, y - 8), mode_letter, fill=color)

    def render_selector(self, draw: ImageDraw.ImageDraw):
        """Render the mode selector overlay."""
        if not self.is_selector_open:
            return

        # Semi-transparent background
        draw.rectangle([0, 0, WIDTH, HEIGHT], fill=(0, 0, 0, 180))

        # Draw mode items in a circle
        n_modes = len(self._available_modes)
        for i, mode in enumerate(self._available_modes):
            angle = (i / n_modes) * 2 * math.pi - math.pi / 2
            item_x = int(CENTER + self.SELECTOR_RADIUS * math.cos(angle))
            item_y = int(self.SELECTOR_CENTER_Y + self.SELECTOR_RADIUS * math.sin(angle))

            mode_info = MODE_INFO.get(mode, MODE_INFO['none'])
            color = mode_info['color']
            is_selected = (i == self._selected_mode_index)
            is_current = (mode == self._current_mode)

            # Item background
            r = self.SELECTOR_ITEM_RADIUS
            if is_selected:
                # Highlight selected
                draw.ellipse([item_x - r - 5, item_y - r - 5, item_x + r + 5, item_y + r + 5],
                            outline=color, width=3)
            if is_current:
                # Mark current mode
                draw.ellipse([item_x - r, item_y - r, item_x + r, item_y + r],
                            fill=(color[0]//3, color[1]//3, color[2]//3))
            else:
                draw.ellipse([item_x - r, item_y - r, item_x + r, item_y + r],
                            fill=(30, 30, 35), outline=(60, 60, 70))

            # Mode icon/letter
            icon = mode_info['icon']
            draw.text((item_x - 8, item_y - 10), icon, fill=color)

            # Mode name below
            name = mode_info['name']
            draw.text((item_x - len(name) * 3, item_y + r + 5), name, fill=(180, 180, 190))

        # Center text
        draw.text((CENTER - 50, CENTER - 10), "Select Mode", fill=(200, 200, 210))

    def render_switching(self, draw: ImageDraw.ImageDraw):
        """Render switching progress overlay."""
        if not self.is_switching:
            return

        # Progress bar
        bar_width = int(200 * self._switching_progress)
        draw.rectangle([CENTER - 100, CENTER - 5, CENTER + 100, CENTER + 5],
                      outline=(100, 100, 110))
        draw.rectangle([CENTER - 100, CENTER - 5, CENTER - 100 + bar_width, CENTER + 5],
                      fill=(0, 200, 255))

        draw.text((CENTER - 40, CENTER - 30), "Switching...", fill=(200, 200, 210))


# Singleton instance
_handler: Optional[GadgetGestureHandler] = None


def get_gesture_handler() -> GadgetGestureHandler:
    """Get singleton gesture handler."""
    global _handler
    if _handler is None:
        _handler = GadgetGestureHandler()
    return _handler
