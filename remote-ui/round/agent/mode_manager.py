"""
SecuBox Eye Remote — Mode Manager
State machine for 4 operating modes: Dashboard, Local, Flash, Gateway.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)


class Mode(Enum):
    """Operating modes for Eye Remote."""
    DASHBOARD = "dashboard"
    LOCAL = "local"
    FLASH = "flash"
    GATEWAY = "gateway"


# Flag file paths (on USB storage partition)
FLAG_FILE_FLASH = Path("/var/lib/secubox/eye-remote/storage/FORCE_FLASH")
FLAG_FILE_GATEWAY = Path("/var/lib/secubox/eye-remote/storage/FORCE_GATEWAY")


class ModeManager:
    """
    State machine for Eye Remote operating modes.

    Modes:
    - DASHBOARD: Real-time SecuBox metrics (when API available)
    - LOCAL: Pi Zero self-monitoring (API unavailable)
    - FLASH: USB storage mode for ESPRESSObin recovery
    - GATEWAY: Multi-SecuBox fleet management

    Mode selection:
    1. Check flag files (FORCE_FLASH, FORCE_GATEWAY)
    2. Auto-detect based on SecuBox API availability
    """

    def __init__(self, initial_mode: Mode = Mode.LOCAL):
        self._current_mode = initial_mode
        self._previous_mode: Optional[Mode] = None
        self._listeners: list[Callable[[Mode, Mode], None]] = []
        self._lock = asyncio.Lock()

    @property
    def current_mode(self) -> Mode:
        """Current operating mode."""
        return self._current_mode

    @property
    def previous_mode(self) -> Optional[Mode]:
        """Previous operating mode (before last transition)."""
        return self._previous_mode

    def add_listener(self, callback: Callable[[Mode, Mode], None]) -> None:
        """Add a mode change listener. Callback receives (old_mode, new_mode)."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[Mode, Mode], None]) -> None:
        """Remove a mode change listener."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    async def set_mode(self, new_mode: Mode) -> bool:
        """
        Transition to a new mode.

        Args:
            new_mode: Target mode

        Returns:
            True if mode changed, False if already in that mode
        """
        async with self._lock:
            if new_mode == self._current_mode:
                return False

            old_mode = self._current_mode
            self._previous_mode = old_mode
            self._current_mode = new_mode

            log.info(f"Mode transition: {old_mode.value} -> {new_mode.value}")

            # Notify listeners
            for listener in self._listeners:
                try:
                    listener(old_mode, new_mode)
                except Exception as e:
                    log.error(f"Mode listener error: {e}")

            return True

    def check_flag_files(self) -> Optional[Mode]:
        """
        Check for flag files that force a specific mode.

        Returns:
            Forced mode or None if no flag files present
        """
        if FLAG_FILE_FLASH.exists():
            log.info(f"Found {FLAG_FILE_FLASH}, forcing FLASH mode")
            return Mode.FLASH

        if FLAG_FILE_GATEWAY.exists():
            log.info(f"Found {FLAG_FILE_GATEWAY}, forcing GATEWAY mode")
            return Mode.GATEWAY

        return None

    async def determine_initial_mode(self, api_available: bool) -> Mode:
        """
        Determine initial mode based on flag files and API availability.

        Args:
            api_available: Whether SecuBox API is reachable

        Returns:
            Appropriate initial mode
        """
        # Check flag files first (highest priority)
        forced_mode = self.check_flag_files()
        if forced_mode:
            await self.set_mode(forced_mode)
            return forced_mode

        # Auto-detect based on API
        if api_available:
            await self.set_mode(Mode.DASHBOARD)
            return Mode.DASHBOARD
        else:
            await self.set_mode(Mode.LOCAL)
            return Mode.LOCAL
