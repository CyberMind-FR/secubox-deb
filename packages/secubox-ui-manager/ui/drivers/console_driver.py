"""
SecuBox UI Manager - Console Driver
====================================

Manages fallback to basic console/getty mode.

This is the terminal state - it always succeeds.
"""

import subprocess
from pathlib import Path
from typing import Optional

from ..lib.debug import get_logger

log = get_logger("console")


class ConsoleDriver:
    """
    Console driver - the final fallback.

    This driver ensures a basic getty/login prompt is available.
    It is designed to always succeed as the last resort.

    Usage:
        driver = ConsoleDriver()
        driver.start()  # Always returns True
    """

    DEFAULT_TTY = "tty1"

    def __init__(self, tty: str = DEFAULT_TTY):
        self._tty = tty
        self._error: str = ""

    def can_start(self) -> bool:
        """Console mode can always start."""
        return True

    def start(self) -> bool:
        """
        Start console mode.

        This ensures getty is running on the specified TTY.
        Always returns True (console is the guaranteed fallback).
        """
        log.info("Starting console mode on %s", self._tty)

        try:
            # Ensure getty is running
            service = f"getty@{self._tty}.service"

            # Try to start/enable getty
            subprocess.run(
                ["systemctl", "start", service],
                capture_output=True,
                timeout=10,
            )

            log.info("Console mode active on %s", self._tty)
            return True

        except Exception as e:
            log.warn("Getty start warning (non-fatal): %s", e)
            # Even if this fails, console mode is considered active
            # The user can still get to a login prompt
            return True

    def stop(self):
        """
        Stop console mode.

        This is a no-op since we don't want to stop getty.
        """
        log.debug("Console stop called (no-op)")

    def is_running(self) -> bool:
        """Check if console is available."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", f"getty@{self._tty}.service"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip() == "active"
        except Exception:
            # Assume it's running if we can't check
            return True

    def get_error(self) -> str:
        """Get the last error (usually empty for console)."""
        return self._error

    def get_status(self) -> dict:
        """Get console status."""
        return {
            "running": self.is_running(),
            "tty": self._tty,
            "error": self._error,
        }

    def switch_to_tty(self) -> bool:
        """
        Switch to the console TTY.

        Uses chvt to switch virtual terminals.
        """
        try:
            # Extract tty number
            tty_num = self._tty.replace("tty", "")

            subprocess.run(
                ["chvt", tty_num],
                capture_output=True,
                timeout=5,
            )
            log.info("Switched to VT%s", tty_num)
            return True

        except Exception as e:
            log.warn("Failed to switch to %s: %s", self._tty, e)
            return False

    @staticmethod
    def ensure_multiple_ttys():
        """
        Ensure multiple TTYs are available for recovery.

        Enables getty on tty2-6 for VT switching.
        """
        log.debug("Ensuring multiple TTYs available")

        for i in range(2, 7):
            service = f"getty@tty{i}.service"
            try:
                subprocess.run(
                    ["systemctl", "enable", "--now", service],
                    capture_output=True,
                    timeout=10,
                )
            except Exception as e:
                log.debug("Failed to enable %s: %s", service, e)
