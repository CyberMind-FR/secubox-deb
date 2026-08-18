# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote — Failover Monitor
Monitors SecuBox API connection and manages graceful degradation.

Staged failover:
- 0s: Stale data + pulsing OFFLINE badge
- 15s: Rings fade to gray
- 60s: Full transition to Local mode
- 60s+ (with auto-mode): Switch to SILENT_STORAGE gadget mode

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum
from typing import Callable, Optional, Any

log = logging.getLogger(__name__)


class FailoverState(Enum):
    """Connection state for failover logic."""
    CONNECTED = "connected"        # API responding normally
    STALE = "stale"                # Data stale, showing OFFLINE badge (0-15s)
    DEGRADED = "degraded"          # Rings grayed out (15-60s)
    DISCONNECTED = "disconnected"  # Full transition to Local mode (60s+)
    SILENT_STORAGE = "silent_storage"  # Switched to silent storage mode (auto-mode)


# Failover timing constants (seconds)
STALE_THRESHOLD = 0      # Immediate on disconnect
DEGRADED_THRESHOLD = 15  # Gray out rings
DISCONNECT_THRESHOLD = 60  # Switch to Local mode
SILENT_STORAGE_THRESHOLD = 60  # Trigger silent storage after this time
RECONNECT_INTERVAL = 10  # Check API every N seconds


class FailoverMonitor:
    """
    Monitors SecuBox API connection and manages failover states.

    Enhanced with auto-mode integration for silent storage fallback:
    - When disconnected for 60+ seconds and auto-mode is enabled,
      triggers switch to silent storage mode
    - Monitors for wake triggers to retry network connection
    """

    def __init__(
        self,
        stale_threshold: float = STALE_THRESHOLD,
        degraded_threshold: float = DEGRADED_THRESHOLD,
        disconnect_threshold: float = DISCONNECT_THRESHOLD,
        reconnect_interval: float = RECONNECT_INTERVAL,
        silent_storage_threshold: float = SILENT_STORAGE_THRESHOLD,
        enable_auto_mode: bool = False,
    ):
        self._state = FailoverState.DISCONNECTED
        self._last_success: Optional[float] = None
        self._listeners: list[Callable[[FailoverState, FailoverState], None]] = []
        self._stale_threshold = stale_threshold
        self._degraded_threshold = degraded_threshold
        self._disconnect_threshold = disconnect_threshold
        self._silent_storage_threshold = silent_storage_threshold
        self._reconnect_interval = reconnect_interval
        self._check_task: Optional[asyncio.Task] = None
        self._api_check_fn: Optional[Callable[[], bool]] = None

        # Auto-mode integration
        self._enable_auto_mode = enable_auto_mode
        self._auto_mode_controller: Optional[Any] = None
        self._silent_storage_triggered = False
        self._last_silent_storage_log: float = 0
        self._log_dedupe_interval = 300  # 5 min between repeated logs

    @property
    def state(self) -> FailoverState:
        return self._state

    @property
    def seconds_since_success(self) -> float:
        if self._last_success is None:
            return float('inf')
        return time.time() - self._last_success

    @property
    def is_in_silent_storage(self) -> bool:
        """Check if currently in silent storage fallback mode."""
        return self._state == FailoverState.SILENT_STORAGE

    def set_auto_mode_controller(self, controller: Any) -> None:
        """Set auto-mode controller for gadget mode switching."""
        self._auto_mode_controller = controller
        self._enable_auto_mode = True

    def add_listener(self, callback: Callable[[FailoverState, FailoverState], None]) -> None:
        self._listeners.append(callback)

    def _notify_listeners(self, old_state: FailoverState, new_state: FailoverState) -> None:
        for listener in self._listeners:
            try:
                listener(old_state, new_state)
            except Exception as e:
                log.error(f"Failover listener error: {e}")

    def record_success(self) -> None:
        """Record successful API connection."""
        self._last_success = time.time()
        self._silent_storage_triggered = False

        if self._state != FailoverState.CONNECTED:
            old_state = self._state
            self._state = FailoverState.CONNECTED
            log.info("API connection restored")
            self._notify_listeners(old_state, self._state)

    def update_state(self) -> FailoverState:
        """Update failover state based on time since last success."""
        elapsed = self.seconds_since_success
        old_state = self._state

        if elapsed <= self._stale_threshold:
            self._state = FailoverState.CONNECTED
            self._silent_storage_triggered = False
        elif elapsed <= self._degraded_threshold:
            self._state = FailoverState.STALE
        elif elapsed <= self._disconnect_threshold:
            self._state = FailoverState.DEGRADED
        elif self._enable_auto_mode and elapsed > self._silent_storage_threshold:
            # Auto-mode: switch to silent storage after threshold
            if not self._silent_storage_triggered:
                self._state = FailoverState.SILENT_STORAGE
                self._silent_storage_triggered = True
            else:
                # Already triggered, stay in silent storage
                self._state = FailoverState.SILENT_STORAGE
        else:
            self._state = FailoverState.DISCONNECTED

        if self._state != old_state:
            log.info(f"Failover state: {old_state.value} -> {self._state.value}")
            self._notify_listeners(old_state, self._state)

        return self._state

    async def _trigger_silent_storage(self) -> None:
        """Trigger switch to silent storage mode via auto-mode controller."""
        if self._auto_mode_controller is None:
            return

        now = time.time()

        # Dedupe logging to avoid spam
        if now - self._last_silent_storage_log > self._log_dedupe_interval:
            log.info("Triggering silent storage fallback mode")
            self._last_silent_storage_log = now

        try:
            # Import here to avoid circular imports
            from .auto_mode_controller import AutoModeState

            # Signal controller to enter silent storage
            if hasattr(self._auto_mode_controller, '_transition_to'):
                await self._auto_mode_controller._transition_to(AutoModeState.SILENT_STORAGE)
        except Exception as e:
            log.error(f"Failed to trigger silent storage: {e}")

    async def start_monitoring(self, api_check_fn: Callable[[], bool]) -> None:
        """Start monitoring API connection."""
        self._api_check_fn = api_check_fn
        self._check_task = asyncio.create_task(self._monitor_loop())

    async def stop_monitoring(self) -> None:
        """Stop monitoring."""
        if self._check_task:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while True:
            try:
                old_state = self._state
                self.update_state()

                # Handle state transitions
                if self._state == FailoverState.SILENT_STORAGE:
                    # Trigger silent storage mode switch
                    if old_state != FailoverState.SILENT_STORAGE:
                        await self._trigger_silent_storage()

                elif self._state == FailoverState.DISCONNECTED and self._api_check_fn:
                    # Try to reconnect
                    try:
                        if await asyncio.wait_for(
                            asyncio.to_thread(self._api_check_fn),
                            timeout=3.0
                        ):
                            self.record_success()
                    except (asyncio.TimeoutError, Exception) as e:
                        log.debug(f"API check failed: {e}")

                await asyncio.sleep(self._reconnect_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Failover monitor error: {e}")
                await asyncio.sleep(self._reconnect_interval)

    def get_status(self) -> dict:
        """Get current failover status."""
        return {
            "state": self._state.value,
            "seconds_since_success": self.seconds_since_success,
            "auto_mode_enabled": self._enable_auto_mode,
            "silent_storage_triggered": self._silent_storage_triggered,
            "thresholds": {
                "stale": self._stale_threshold,
                "degraded": self._degraded_threshold,
                "disconnect": self._disconnect_threshold,
                "silent_storage": self._silent_storage_threshold,
            }
        }
