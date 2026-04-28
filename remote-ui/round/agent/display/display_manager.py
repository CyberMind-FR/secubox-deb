#!/usr/bin/env python3
"""
SecuBox Eye Remote - Display Manager

Master display controller that manages dashboard priority:
1. First boot sensor (if not done)
2. Fallback manager (main dashboard)
3. Logo fallback (endless - if all else fails)

Automatically restarts displays if they crash.
Logo is the endless fallback when dashboards stop.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import os
import sys
import time
import signal
import subprocess
from pathlib import Path
from enum import Enum

# Display script locations
SCRIPT_DIR = Path(__file__).parent
FIRSTBOOT_SENSOR = SCRIPT_DIR / "firstboot_sensor.py"
FALLBACK_MANAGER = SCRIPT_DIR / "fallback" / "fallback_manager.py"
LOGO_FALLBACK = SCRIPT_DIR / "logo_fallback.py"

# State files
FIRSTBOOT_DONE = Path("/etc/secubox/eye-remote/.firstboot_done")
TOUCHPAD_DISABLED = Path("/etc/secubox/eye-remote/.touchpad_disabled")

# Fallback scripts if main ones not found
FALLBACK_SCRIPTS = [
    Path("/tmp/fallback_manager.py"),
    Path("/tmp/logo_fallback.py"),
]


class DisplayMode(Enum):
    FIRSTBOOT = "firstboot"
    DASHBOARD = "dashboard"
    LOGO = "logo"


class DisplayManager:
    """Manages display priority and automatic fallback to logo."""

    def __init__(self):
        self._current_mode = None
        self._current_process = None
        self._running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals."""
        print(f"\nReceived signal {signum}, shutting down...")
        self._running = False
        self._stop_current()

    def _stop_current(self):
        """Stop current display process."""
        if self._current_process and self._current_process.poll() is None:
            print(f"Stopping {self._current_mode}...")
            self._current_process.terminate()
            try:
                self._current_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._current_process.kill()
            self._current_process = None

    def _find_script(self, primary: Path, fallbacks: list = None) -> Path:
        """Find script, checking fallbacks if primary not found."""
        if primary.exists():
            return primary
        if fallbacks:
            for fb in fallbacks:
                if fb.exists():
                    return fb
        return primary  # Return primary anyway, will fail with clear error

    def _start_display(self, mode: DisplayMode, script: Path) -> bool:
        """Start a display script."""
        if not script.exists():
            print(f"Script not found: {script}")
            return False

        print(f"Starting {mode.value}: {script}")
        try:
            self._current_process = subprocess.Popen(
                [sys.executable, str(script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self._current_mode = mode
            return True
        except Exception as e:
            print(f"Failed to start {mode.value}: {e}")
            return False

    def _check_process(self) -> bool:
        """Check if current process is still running."""
        if self._current_process is None:
            return False
        return self._current_process.poll() is None

    def run(self):
        """Main display manager loop."""
        print("SecuBox Eye Remote - Display Manager")
        print("=" * 40)

        while self._running:
            try:
                # Determine what should be running
                target_mode = self._get_target_mode()

                # If current process died or wrong mode, start correct one
                if not self._check_process() or self._current_mode != target_mode:
                    self._stop_current()
                    self._start_mode(target_mode)

                # Wait a bit before checking again
                time.sleep(2)

            except Exception as e:
                print(f"Error in display manager: {e}")
                time.sleep(5)

        # Cleanup
        self._stop_current()
        print("Display manager stopped")

    def _get_target_mode(self) -> DisplayMode:
        """Determine which display mode should be active."""
        # First boot takes priority if not done
        if not FIRSTBOOT_DONE.exists() and FIRSTBOOT_SENSOR.exists():
            return DisplayMode.FIRSTBOOT

        # Main dashboard
        fallback_script = self._find_script(FALLBACK_MANAGER, FALLBACK_SCRIPTS)
        if fallback_script.exists():
            return DisplayMode.DASHBOARD

        # Ultimate fallback: logo
        return DisplayMode.LOGO

    def _start_mode(self, mode: DisplayMode):
        """Start the appropriate display mode."""
        if mode == DisplayMode.FIRSTBOOT:
            script = self._find_script(FIRSTBOOT_SENSOR)
            if not self._start_display(mode, script):
                # First boot failed, try dashboard
                self._start_mode(DisplayMode.DASHBOARD)

        elif mode == DisplayMode.DASHBOARD:
            script = self._find_script(FALLBACK_MANAGER, FALLBACK_SCRIPTS)
            if not self._start_display(mode, script):
                # Dashboard failed, fall back to logo
                self._start_mode(DisplayMode.LOGO)

        elif mode == DisplayMode.LOGO:
            script = self._find_script(LOGO_FALLBACK, [Path("/tmp/logo_fallback.py")])
            if not self._start_display(mode, script):
                print("CRITICAL: No display available!")
                # Try inline logo as last resort
                self._run_inline_logo()

    def _run_inline_logo(self):
        """Run minimal inline logo if all scripts fail."""
        print("Running inline minimal logo...")
        try:
            from PIL import Image, ImageDraw
            import math

            while self._running:
                t = time.time()
                pulse = (math.sin(t * 0.5) + 1) / 2

                img = Image.new('RGBA', (480, 480), (5, 5, 12, 255))
                draw = ImageDraw.Draw(img)

                # Simple pulsing circle
                r = 80 + pulse * 20
                color = (255, int(80 + pulse * 40), 30)
                draw.ellipse([240-r, 225-r, 240+r, 225+r], fill=color)

                # Text
                draw.text((200, 400), "SECUBOX", fill=(150, 140, 120))

                with open('/dev/fb0', 'wb') as fb:
                    fb.write(img.convert('RGBA').tobytes('raw', 'BGRA'))

                time.sleep(0.05)

        except Exception as e:
            print(f"Inline logo failed: {e}")


def main():
    """Entry point."""
    manager = DisplayManager()
    manager.run()


if __name__ == "__main__":
    main()
