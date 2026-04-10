"""
SecuBox UI Manager - Health Monitoring
=======================================

Monitors UI health and triggers fallback on failure.
"""

import asyncio
import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable, List

from .debug import get_logger
from .state_machine import UIState

log = get_logger("health")


@dataclass
class HealthStatus:
    """Current health status."""
    healthy: bool = True
    mode: str = ""
    uptime: float = 0.0
    checks_passed: int = 0
    checks_failed: int = 0
    last_check: float = 0.0
    last_error: str = ""
    x11_running: bool = False
    chromium_running: bool = False
    tui_running: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "healthy": self.healthy,
            "mode": self.mode,
            "uptime": self.uptime,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "last_check": self.last_check,
            "last_error": self.last_error,
            "x11_running": self.x11_running,
            "chromium_running": self.chromium_running,
            "tui_running": self.tui_running,
        }


class HealthMonitor:
    """
    Monitor UI health and trigger fallback on failure.

    Usage:
        monitor = HealthMonitor()
        monitor.set_mode("kui")
        monitor.on_failure(handle_failure)

        # Start monitoring (async)
        await monitor.start()

        # Or check manually
        status = monitor.check()
    """

    def __init__(
        self,
        check_interval: float = 10.0,
        failure_threshold: int = 3,
        health_file: Optional[Path] = None,
    ):
        self.check_interval = check_interval
        self.failure_threshold = failure_threshold
        self.health_file = health_file or Path("/run/secubox/ui/health.json")

        self._status = HealthStatus()
        self._start_time: Optional[float] = None
        self._consecutive_failures = 0
        self._failure_callbacks: List[Callable[[HealthStatus], None]] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def set_mode(self, mode: str):
        """Set the current UI mode being monitored."""
        self._status.mode = mode
        self._status.healthy = True
        self._status.checks_passed = 0
        self._status.checks_failed = 0
        self._start_time = time.time()
        self._consecutive_failures = 0
        log.info("Monitoring mode: %s", mode)

    def on_failure(self, callback: Callable[[HealthStatus], None]):
        """Register a callback for health failures."""
        self._failure_callbacks.append(callback)

    def check(self) -> HealthStatus:
        """
        Perform a health check.

        Returns:
            Current health status
        """
        self._status.last_check = time.time()

        if self._start_time:
            self._status.uptime = time.time() - self._start_time

        try:
            if self._status.mode == "kui":
                self._check_kui()
            elif self._status.mode == "tui":
                self._check_tui()
            elif self._status.mode == "console":
                self._check_console()
            else:
                # Unknown mode, assume healthy
                self._status.healthy = True

            if self._status.healthy:
                self._status.checks_passed += 1
                self._consecutive_failures = 0
                self._status.last_error = ""
            else:
                self._status.checks_failed += 1
                self._consecutive_failures += 1

        except Exception as e:
            self._status.healthy = False
            self._status.last_error = str(e)
            self._status.checks_failed += 1
            self._consecutive_failures += 1
            log.error("Health check error: %s", e)

        # Save status
        self._save_status()

        # Trigger failure callbacks if threshold exceeded
        if self._consecutive_failures >= self.failure_threshold:
            log.error(
                "Health check failed %d times, triggering failure callbacks",
                self._consecutive_failures,
            )
            self._fire_failure_callbacks()

        return self._status

    def _check_kui(self):
        """Check KUI (X11 + Chromium) health."""
        # Check X11
        self._status.x11_running = self._process_running("Xorg")

        # Check Chromium
        self._status.chromium_running = self._process_running("chromium")

        if not self._status.x11_running:
            self._status.healthy = False
            self._status.last_error = "X11 not running"
        elif not self._status.chromium_running:
            self._status.healthy = False
            self._status.last_error = "Chromium not running"
        else:
            self._status.healthy = True

    def _check_tui(self):
        """Check TUI health."""
        # Check if TUI process is running
        self._status.tui_running = (
            self._process_running("secubox-tui") or
            self._process_running("python.*textual")
        )

        if not self._status.tui_running:
            self._status.healthy = False
            self._status.last_error = "TUI not running"
        else:
            self._status.healthy = True

    def _check_console(self):
        """Check console health."""
        # Console is always healthy if we got this far
        # Just check that getty is running
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "getty@tty1.service"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self._status.healthy = result.stdout.strip() == "active"
            if not self._status.healthy:
                self._status.last_error = "getty not active"
        except Exception as e:
            # Even if check fails, console mode is resilient
            self._status.healthy = True
            log.debug("Console check warning: %s", e)

    def _process_running(self, pattern: str) -> bool:
        """Check if a process matching pattern is running."""
        try:
            result = subprocess.run(
                ["pgrep", "-f", pattern],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _save_status(self):
        """Save health status to file."""
        try:
            self.health_file.parent.mkdir(parents=True, exist_ok=True)
            self.health_file.write_text(json.dumps(self._status.to_dict(), indent=2))
        except IOError as e:
            log.debug("Failed to save health status: %s", e)

    def _fire_failure_callbacks(self):
        """Fire all registered failure callbacks."""
        for callback in self._failure_callbacks:
            try:
                callback(self._status)
            except Exception as e:
                log.error("Failure callback error: %s", e)

    async def start(self):
        """Start the health monitoring loop."""
        if self._running:
            return

        self._running = True
        log.info("Health monitor started (interval: %.1fs)", self.check_interval)

        while self._running:
            self.check()
            await asyncio.sleep(self.check_interval)

    def stop(self):
        """Stop the health monitoring loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        log.info("Health monitor stopped")

    def get_status(self) -> HealthStatus:
        """Get the current health status without checking."""
        return self._status

    def is_healthy(self) -> bool:
        """Quick check if currently healthy."""
        return self._status.healthy

    def force_failure(self, error: str):
        """Force a failure state (for testing or manual intervention)."""
        self._status.healthy = False
        self._status.last_error = error
        self._consecutive_failures = self.failure_threshold
        self._fire_failure_callbacks()
