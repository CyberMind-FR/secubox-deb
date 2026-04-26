"""
SecuBox Eye Remote — Failover Monitor
Monitors SecuBox API connection and manages graceful degradation.

Staged failover:
- 0s: Stale data + pulsing OFFLINE badge
- 15s: Rings fade to gray
- 60s: Full transition to Local mode

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum
from typing import Callable, Optional

log = logging.getLogger(__name__)


class FailoverState(Enum):
    """Connection state for failover logic."""
    CONNECTED = "connected"      # API responding normally
    STALE = "stale"              # Data stale, showing OFFLINE badge (0-15s)
    DEGRADED = "degraded"        # Rings grayed out (15-60s)
    DISCONNECTED = "disconnected"  # Full transition to Local mode (60s+)


# Failover timing constants (seconds)
STALE_THRESHOLD = 0      # Immediate on disconnect
DEGRADED_THRESHOLD = 15  # Gray out rings
DISCONNECT_THRESHOLD = 60  # Switch to Local mode
RECONNECT_INTERVAL = 10  # Check API every N seconds


class FailoverMonitor:
    """
    Monitors SecuBox API connection and manages failover states.
    """

    def __init__(
        self,
        stale_threshold: float = STALE_THRESHOLD,
        degraded_threshold: float = DEGRADED_THRESHOLD,
        disconnect_threshold: float = DISCONNECT_THRESHOLD,
        reconnect_interval: float = RECONNECT_INTERVAL,
    ):
        self._state = FailoverState.DISCONNECTED
        self._last_success: Optional[float] = None
        self._listeners: list[Callable[[FailoverState, FailoverState], None]] = []
        self._stale_threshold = stale_threshold
        self._degraded_threshold = degraded_threshold
        self._disconnect_threshold = disconnect_threshold
        self._reconnect_interval = reconnect_interval
        self._check_task: Optional[asyncio.Task] = None
        self._api_check_fn: Optional[Callable[[], bool]] = None

    @property
    def state(self) -> FailoverState:
        return self._state

    @property
    def seconds_since_success(self) -> float:
        if self._last_success is None:
            return float('inf')
        return time.time() - self._last_success

    def add_listener(self, callback: Callable[[FailoverState, FailoverState], None]) -> None:
        self._listeners.append(callback)

    def _notify_listeners(self, old_state: FailoverState, new_state: FailoverState) -> None:
        for listener in self._listeners:
            try:
                listener(old_state, new_state)
            except Exception as e:
                log.error(f"Failover listener error: {e}")

    def record_success(self) -> None:
        self._last_success = time.time()
        if self._state != FailoverState.CONNECTED:
            old_state = self._state
            self._state = FailoverState.CONNECTED
            log.info("API connection restored")
            self._notify_listeners(old_state, self._state)

    def update_state(self) -> FailoverState:
        elapsed = self.seconds_since_success
        old_state = self._state

        if elapsed <= self._stale_threshold:
            self._state = FailoverState.CONNECTED
        elif elapsed <= self._degraded_threshold:
            self._state = FailoverState.STALE
        elif elapsed <= self._disconnect_threshold:
            self._state = FailoverState.DEGRADED
        else:
            self._state = FailoverState.DISCONNECTED

        if self._state != old_state:
            log.info(f"Failover state: {old_state.value} -> {self._state.value}")
            self._notify_listeners(old_state, self._state)

        return self._state

    async def start_monitoring(self, api_check_fn: Callable[[], bool]) -> None:
        self._api_check_fn = api_check_fn
        self._check_task = asyncio.create_task(self._monitor_loop())

    async def stop_monitoring(self) -> None:
        if self._check_task:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        while True:
            try:
                self.update_state()
                if self._state == FailoverState.DISCONNECTED and self._api_check_fn:
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
