"""
SecuBox UI Manager - Fallback Chain
====================================

Manages the fallback sequence when UI modes fail.

Default priority: KUI -> TUI -> Console
Console is terminal state (always succeeds).
"""

from dataclasses import dataclass, field
from typing import List, Optional, Callable
from pathlib import Path
import os

from .debug import get_logger

log = get_logger("fallback")


@dataclass
class FallbackConfig:
    """Configuration for fallback behavior."""
    priority: List[str] = field(default_factory=lambda: ["kui", "tui", "console"])
    timeout_seconds: int = 30
    max_retries: int = 2

    @classmethod
    def from_cmdline(cls) -> "FallbackConfig":
        """Parse kernel cmdline for UI mode override."""
        config = cls()

        try:
            cmdline = Path("/proc/cmdline").read_text()

            # Parse secubox.ui=<mode>
            for part in cmdline.split():
                if part.startswith("secubox.ui="):
                    mode = part.split("=", 1)[1].strip()
                    if mode in ("kui", "tui", "console"):
                        # Move requested mode to front
                        if mode in config.priority:
                            config.priority.remove(mode)
                        config.priority.insert(0, mode)
                        log.info("Cmdline override: %s first", mode)

        except (IOError, OSError) as e:
            log.debug("Failed to read cmdline: %s", e)

        return config


class FallbackChain:
    """
    Manages the UI mode fallback sequence.

    Usage:
        chain = FallbackChain()
        mode = chain.get_next()  # Returns first mode to try

        # On failure:
        chain.mark_failed(mode, "X11 failed to start")
        next_mode = chain.get_next()  # Returns next in chain

        # Continue until console (always succeeds)
    """

    def __init__(self, config: Optional[FallbackConfig] = None):
        self.config = config or FallbackConfig.from_cmdline()
        self._failed: dict[str, str] = {}  # mode -> error
        self._attempts: dict[str, int] = {}  # mode -> attempt count
        self._current_index: int = 0

        log.debug("Fallback chain: %s", self.config.priority)

    @property
    def priority(self) -> List[str]:
        """Get the priority list."""
        return self.config.priority

    @property
    def failed_modes(self) -> dict[str, str]:
        """Get dict of failed modes and their errors."""
        return self._failed.copy()

    def get_next(self) -> Optional[str]:
        """
        Get the next mode to try.

        Returns:
            Mode name or None if all modes exhausted
        """
        for mode in self.config.priority[self._current_index:]:
            # Skip failed modes that exceeded retries
            attempts = self._attempts.get(mode, 0)
            if mode in self._failed and attempts >= self.config.max_retries:
                continue

            return mode

        return None

    def get_current(self) -> Optional[str]:
        """Get the current mode being tried."""
        if self._current_index < len(self.config.priority):
            return self.config.priority[self._current_index]
        return None

    def mark_failed(self, mode: str, error: str):
        """
        Mark a mode as failed.

        Args:
            mode: The mode that failed
            error: Error description
        """
        self._failed[mode] = error
        self._attempts[mode] = self._attempts.get(mode, 0) + 1

        log.warn(
            "Mode %s failed (attempt %d/%d): %s",
            mode,
            self._attempts[mode],
            self.config.max_retries,
            error,
        )

        # Advance to next mode if retries exceeded
        if self._attempts[mode] >= self.config.max_retries:
            try:
                idx = self.config.priority.index(mode)
                if idx >= self._current_index:
                    self._current_index = idx + 1
            except ValueError:
                pass

    def mark_success(self, mode: str):
        """Mark a mode as successfully started."""
        log.info("Mode %s started successfully", mode)
        # Remove from failed if it was there
        self._failed.pop(mode, None)

    def reset(self):
        """Reset the fallback chain."""
        self._failed.clear()
        self._attempts.clear()
        self._current_index = 0
        log.info("Fallback chain reset")

    def can_retry(self, mode: str) -> bool:
        """Check if a mode can be retried."""
        return self._attempts.get(mode, 0) < self.config.max_retries

    def get_remaining(self) -> List[str]:
        """Get list of modes that haven't permanently failed."""
        remaining = []
        for mode in self.config.priority:
            if mode not in self._failed or self.can_retry(mode):
                remaining.append(mode)
        return remaining

    def is_exhausted(self) -> bool:
        """Check if all modes have been exhausted."""
        # Console always works, so we're only exhausted if we've
        # tried everything including console
        return self.get_next() is None

    def get_fallback_report(self) -> dict:
        """Get a report of the fallback state."""
        return {
            "priority": self.config.priority,
            "failed": self._failed,
            "attempts": self._attempts,
            "current_index": self._current_index,
            "next_mode": self.get_next(),
            "remaining": self.get_remaining(),
            "exhausted": self.is_exhausted(),
        }
