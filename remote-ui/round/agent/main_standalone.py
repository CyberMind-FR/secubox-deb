#!/usr/bin/env python3
"""
SecuBox Eye Remote - Standalone Simple Menu
Minimal version with radial menu + touch selection.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
import asyncio
import logging
import math
import sys
from pathlib import Path

# Configure logging early
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/eye-agent.log", mode="a")
    ]
)
log = logging.getLogger("eye-standalone")

# Add agent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Display constants
CENTER_X = 240
CENTER_Y = 240
CENTER_ZONE_RADIUS = 60
OUTER_ZONE_RADIUS = 220


def get_slice_from_touch(x: int, y: int):
    """Convert touch coordinates to slice index (0-5) or None."""
    dx = x - CENTER_X
    dy = y - CENTER_Y
    distance = math.sqrt(dx * dx + dy * dy)

    if distance < CENTER_ZONE_RADIUS:
        return None  # Center zone
    if distance > OUTER_ZONE_RADIUS:
        return None  # Outside

    # Angle from top, clockwise
    angle = math.degrees(math.atan2(dx, -dy))
    if angle < 0:
        angle += 360

    slice_index = int((angle + 30) % 360 // 60)
    return slice_index


def find_touch_device():
    """Find the touchscreen device path."""
    try:
        import evdev
    except ImportError:
        log.error("evdev not installed")
        return None

    log.info("Scanning for touch devices...")
    candidates = []

    for path in sorted(Path("/dev/input").glob("event*")):
        try:
            dev = evdev.InputDevice(str(path))
            name_lower = dev.name.lower()
            log.debug(f"  Checking: {dev.name} at {path}")

            caps = dev.capabilities()

            # Check for ABS events (touch/position)
            if evdev.ecodes.EV_ABS in caps:
                abs_caps = caps[evdev.ecodes.EV_ABS]
                abs_codes = [c[0] if isinstance(c, tuple) else c for c in abs_caps]

                # FT5x06 uses ABS_MT_POSITION_X/Y
                has_mt = (evdev.ecodes.ABS_MT_POSITION_X in abs_codes or
                          evdev.ecodes.ABS_X in abs_codes)

                if has_mt:
                    log.info(f"  Found ABS device: {dev.name}")
                    # Prioritize ft5x06
                    if 'ft5' in name_lower:
                        candidates.insert(0, (str(path), dev.name))
                    else:
                        candidates.append((str(path), dev.name))
            dev.close()
        except Exception as e:
            log.debug(f"  Could not check {path}: {e}")

    if candidates:
        path, name = candidates[0]
        log.info(f"Selected touch device: {name} at {path}")
        return path

    log.warning("No touch device found")
    return None


async def main():
    """Main entry point."""
    log.info("=== SecuBox Eye Remote - Standalone v1.2 ===")

    # Import components
    try:
        from radial_renderer import RadialRenderer
        from menu_navigator import MenuNavigator
        log.info("Components imported successfully")
    except ImportError as e:
        log.error(f"Failed to import components: {e}")
        return 1

    # Initialize
    renderer = RadialRenderer()
    navigator = MenuNavigator()
    navigator.enter_menu()

    # Initial render
    def render():
        try:
            renderer.render(navigator.state)
            renderer.write_to_framebuffer()
            log.debug(f"Rendered menu: {navigator.state.current_menu.name}, idx={navigator.state.selected_index}")
        except Exception as e:
            log.error(f"Render error: {e}")

    log.info("Rendering initial menu...")
    render()
    log.info("Initial render complete")

    # Find touch device with retries
    touch_path = None
    for attempt in range(10):
        touch_path = find_touch_device()
        if touch_path:
            break
        log.info(f"Waiting for touch device... (attempt {attempt + 1}/10)")
        await asyncio.sleep(1)

    if not touch_path:
        log.warning("No touch device after 10 attempts - display only mode")
        while True:
            await asyncio.sleep(60)

    # Open touch device
    try:
        import evdev
        touch_dev = evdev.InputDevice(touch_path)
        log.info(f"Touch device opened: {touch_dev.name}")
    except Exception as e:
        log.error(f"Failed to open touch device: {e}")
        while True:
            await asyncio.sleep(60)
        return 1

    # Touch state
    current_slot = 0
    slots = {}  # slot -> {x, y, tracking_id}

    log.info("Starting touch event loop...")

    try:
        async for event in touch_dev.async_read_loop():
            if event.type == evdev.ecodes.EV_ABS:
                if event.code == evdev.ecodes.ABS_MT_SLOT:
                    current_slot = event.value

                elif event.code == evdev.ecodes.ABS_MT_TRACKING_ID:
                    if event.value >= 0:
                        # Touch start
                        slots[current_slot] = {"x": 0, "y": 0, "id": event.value}
                    else:
                        # Touch end
                        if current_slot in slots:
                            x = slots[current_slot]["x"]
                            y = slots[current_slot]["y"]
                            log.info(f"Touch released at ({x}, {y})")

                            # Process tap
                            slice_idx = get_slice_from_touch(x, y)
                            if slice_idx is not None:
                                log.info(f"Tap on slice {slice_idx}")
                                navigator.state.selected_index = slice_idx
                                action = navigator.select_current()
                                if action:
                                    log.info(f"Action: {action}")
                                render()
                            elif x > CENTER_X - 60 and x < CENTER_X + 60 and y > CENTER_Y - 60 and y < CENTER_Y + 60:
                                # Center tap - go back
                                log.info("Center tap - going back")
                                navigator.go_back()
                                render()

                            del slots[current_slot]

                elif event.code == evdev.ecodes.ABS_MT_POSITION_X:
                    if current_slot in slots:
                        slots[current_slot]["x"] = event.value

                elif event.code == evdev.ecodes.ABS_MT_POSITION_Y:
                    if current_slot in slots:
                        slots[current_slot]["y"] = event.value

    except asyncio.CancelledError:
        log.info("Event loop cancelled")
    except Exception as e:
        log.error(f"Event loop error: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        touch_dev.close()

    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        log.info("Interrupted")
        sys.exit(0)
    except Exception as e:
        log.error(f"Fatal error: {e}")
        import traceback
        log.error(traceback.format_exc())
        sys.exit(1)
