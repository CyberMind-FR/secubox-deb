"""
SecuBox UI Manager - Main Manager
==================================

Central orchestrator for UI mode management.
"""

import asyncio
import signal
import sys
import tomllib
from pathlib import Path
from typing import Optional, Dict, Any

from .lib.debug import get_logger, set_debug_level, DebugLevel
from .lib.state_machine import UIStateMachine, UIState
from .lib.hypervisor import HypervisorDetector
from .lib.display import DisplayDetector
from .lib.fallback import FallbackChain, FallbackConfig
from .lib.health import HealthMonitor

from .drivers.kui_driver import KUIDriver
from .drivers.tui_driver import TUIDriver
from .drivers.console_driver import ConsoleDriver

log = get_logger("manager")


class UIManager:
    """
    Main UI Manager orchestrator.

    Coordinates:
        - State machine transitions
        - Mode detection and selection
        - Driver lifecycle
        - Health monitoring
        - Fallback handling

    Usage:
        manager = UIManager()
        await manager.run()
    """

    DEFAULT_CONFIG_PATHS = [
        Path("/etc/secubox/ui/ui.toml"),
        Path("/usr/lib/secubox/ui/config/ui.toml"),
    ]

    def __init__(self, config_path: Optional[Path] = None):
        self._config = self._load_config(config_path)
        self._apply_debug_config()

        self._state_machine = UIStateMachine()
        self._hypervisor = HypervisorDetector()
        self._display = DisplayDetector()
        self._fallback = FallbackChain()
        self._health = HealthMonitor(
            check_interval=self._config.get("health", {}).get("check_interval", 10.0),
            failure_threshold=self._config.get("health", {}).get("failure_threshold", 3),
        )

        # Drivers
        self._drivers: Dict[str, Any] = {
            "kui": KUIDriver(),
            "tui": TUIDriver(),
            "console": ConsoleDriver(),
        }
        self._active_driver: Optional[Any] = None
        self._active_mode: Optional[str] = None

        # Shutdown handling
        self._shutdown_event = asyncio.Event()
        self._setup_signal_handlers()

        # Register health failure callback
        self._health.on_failure(self._on_health_failure)

    def _load_config(self, path: Optional[Path] = None) -> dict:
        """Load configuration from TOML file."""
        paths_to_try = [path] if path else self.DEFAULT_CONFIG_PATHS

        for config_path in paths_to_try:
            if config_path and config_path.exists():
                try:
                    with open(config_path, "rb") as f:
                        config = tomllib.load(f)
                        log.info("Loaded config from %s", config_path)
                        return config
                except Exception as e:
                    log.warn("Failed to load config from %s: %s", config_path, e)

        log.debug("Using default configuration")
        return {}

    def _apply_debug_config(self):
        """Apply debug settings from config."""
        debug_config = self._config.get("debug", {})
        level = debug_config.get("level", 1)
        set_debug_level(level)

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def handle_signal(signum, frame):
            log.info("Received signal %d, shutting down", signum)
            self._shutdown_event.set()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

    async def run(self):
        """
        Main run loop.

        Executes the state machine from INIT to a terminal state.
        """
        log.info("SecuBox UI Manager starting")

        try:
            # INIT -> DETECTING
            self._state_machine.transition(UIState.DETECTING)
            hypervisor_info = self._hypervisor.detect()
            display_info = self._display.detect()

            self._state_machine.transition(
                UIState.SELECTING,
                hypervisor=hypervisor_info.type,
                graphics=hypervisor_info.graphics,
            )

            # Get mode to try
            mode = self._get_initial_mode()
            log.info("Initial mode: %s", mode)

            # Start mode (with fallback loop)
            while not self._shutdown_event.is_set():
                success = await self._start_mode(mode)

                if success:
                    # Mode started successfully
                    self._health.set_mode(mode)

                    # Run health monitoring loop
                    await self._run_monitoring_loop()

                    # If we exit the loop, either shutdown or fallback
                    if self._shutdown_event.is_set():
                        break

                # Mode failed or exited, try fallback
                self._fallback.mark_failed(mode, self._get_driver_error(mode))

                next_mode = self._fallback.get_next()
                if next_mode:
                    self._state_machine.transition(UIState.FALLBACK)
                    mode = next_mode
                    log.info("Falling back to: %s", mode)
                else:
                    # No more fallbacks
                    log.error("All UI modes exhausted")
                    self._state_machine.transition(UIState.ERROR, error="All modes failed")
                    break

        except Exception as e:
            log.error("Fatal error: %s", e)
            self._state_machine.transition(UIState.ERROR, error=str(e))

        finally:
            self._cleanup()

    def _get_initial_mode(self) -> str:
        """Determine the initial mode to try."""
        # Check config for default
        default = self._config.get("general", {}).get("default_mode", "auto")

        if default != "auto" and default in self._drivers:
            return default

        # Use fallback chain
        mode = self._fallback.get_next()
        return mode or "console"

    async def _start_mode(self, mode: str) -> bool:
        """
        Start a UI mode.

        Args:
            mode: Mode name (kui, tui, console)

        Returns:
            True if started successfully
        """
        driver = self._drivers.get(mode)
        if not driver:
            log.error("Unknown mode: %s", mode)
            return False

        # Check if mode can start
        if not driver.can_start():
            log.warn("Mode %s cannot start: %s", mode, driver.get_error())
            return False

        # Transition to starting state
        starting_state = {
            "kui": UIState.KUI_STARTING,
            "tui": UIState.TUI_STARTING,
            "console": UIState.CONSOLE_STARTING,
        }.get(mode)

        if starting_state:
            self._state_machine.transition(starting_state, mode=mode)

        # Start the driver
        log.info("Starting mode: %s", mode)
        success = driver.start()

        if success:
            ok_state = {
                "kui": UIState.KUI_OK,
                "tui": UIState.TUI_OK,
                "console": UIState.CONSOLE_OK,
            }.get(mode)

            if ok_state:
                self._state_machine.transition(ok_state)

            self._active_driver = driver
            self._active_mode = mode
            self._fallback.mark_success(mode)

        else:
            failed_state = {
                "kui": UIState.KUI_FAILED,
                "tui": UIState.TUI_FAILED,
            }.get(mode)

            if failed_state:
                self._state_machine.transition(failed_state, error=driver.get_error())

        return success

    def _get_driver_error(self, mode: str) -> str:
        """Get error from driver."""
        driver = self._drivers.get(mode)
        return driver.get_error() if driver else "Unknown mode"

    async def _run_monitoring_loop(self):
        """Run the health monitoring loop."""
        log.debug("Starting monitoring loop")

        while not self._shutdown_event.is_set():
            # Check health
            status = self._health.check()

            if not status.healthy:
                log.warn("Health check failed: %s", status.last_error)
                # Health monitor will trigger failure callback after threshold
                break

            # Wait for next check or shutdown
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self._health.check_interval,
                )
                # If we get here, shutdown was signaled
                break
            except asyncio.TimeoutError:
                # Normal timeout, continue monitoring
                pass

    def _on_health_failure(self, status):
        """Handle health failure callback."""
        log.error("Health failure detected, triggering fallback")

        if self._active_mode:
            failed_state = {
                "kui": UIState.KUI_FAILED,
                "tui": UIState.TUI_FAILED,
            }.get(self._active_mode)

            if failed_state:
                self._state_machine.transition(failed_state, error=status.last_error)

        # Stop current driver
        if self._active_driver:
            self._active_driver.stop()
            self._active_driver = None

    def _cleanup(self):
        """Cleanup on shutdown."""
        log.info("Cleaning up")

        self._health.stop()

        if self._active_driver:
            self._active_driver.stop()

    def get_status(self) -> dict:
        """Get current manager status."""
        return {
            "state": self._state_machine.status(),
            "mode": self._active_mode,
            "health": self._health.get_status().to_dict(),
            "fallback": self._fallback.get_fallback_report(),
        }


async def main():
    """Main entry point."""
    manager = UIManager()
    await manager.run()


def run():
    """Synchronous entry point."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
