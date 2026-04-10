"""
SecuBox UI Manager - Modular Debug System
==========================================

Debug levels (SECUBOX_UI_DEBUG environment variable):
    0: SILENT  - No output
    1: ERROR   - Errors only
    2: WARN    - Warnings and errors
    3: INFO    - Info, warnings, errors
    4: DEBUG   - Debug traces and above
    5: TRACE   - Full trace including syscalls

Component filtering (SECUBOX_UI_DEBUG_COMPONENTS):
    Comma-separated list: state,kui,tui,hypervisor,health,display
    Empty = all components enabled

Output channels:
    - journald: Structured JSON logs (always)
    - console: Colored stderr if TTY available
    - fifo: /run/secubox/ui/debug.fifo for external tools
"""

import os
import sys
import json
import logging
import time
from enum import IntEnum
from pathlib import Path
from typing import Optional, Set
from dataclasses import dataclass, field


class DebugLevel(IntEnum):
    """Debug verbosity levels."""
    SILENT = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    TRACE = 5


# ANSI color codes for console output
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"


@dataclass
class DebugConfig:
    """Debug system configuration."""
    level: DebugLevel = DebugLevel.ERROR
    components: Set[str] = field(default_factory=set)
    enable_console: bool = True
    enable_fifo: bool = True
    fifo_path: Path = field(default_factory=lambda: Path("/run/secubox/ui/debug.fifo"))

    @classmethod
    def from_environment(cls) -> "DebugConfig":
        """Load configuration from environment variables."""
        level_str = os.environ.get("SECUBOX_UI_DEBUG", "1")
        try:
            level = DebugLevel(int(level_str))
        except (ValueError, TypeError):
            level = DebugLevel.ERROR

        components_str = os.environ.get("SECUBOX_UI_DEBUG_COMPONENTS", "")
        components = set(c.strip() for c in components_str.split(",") if c.strip())

        return cls(
            level=level,
            components=components,
            enable_console=sys.stderr.isatty(),
            enable_fifo=os.path.exists("/run/secubox"),
        )


class DebugManager:
    """
    Centralized debug manager for all UI components.

    Usage:
        debug = DebugManager()
        log = debug.get_logger("kui")
        log.info("Starting X11...")
        log.debug("Driver: %s", driver_name)
    """

    _instance: Optional["DebugManager"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.config = DebugConfig.from_environment()
        self._loggers: dict[str, "ComponentLogger"] = {}
        self._fifo_fd: Optional[int] = None
        self._start_time = time.monotonic()
        self._initialized = True

        # Setup FIFO if enabled
        if self.config.enable_fifo:
            self._setup_fifo()

    def _setup_fifo(self):
        """Create debug FIFO for external tools."""
        try:
            fifo_path = self.config.fifo_path
            fifo_path.parent.mkdir(parents=True, exist_ok=True)

            if not fifo_path.exists():
                os.mkfifo(str(fifo_path), 0o640)

            # Open non-blocking
            self._fifo_fd = os.open(str(fifo_path), os.O_WRONLY | os.O_NONBLOCK)
        except (OSError, IOError):
            self._fifo_fd = None

    def get_logger(self, component: str) -> "ComponentLogger":
        """Get or create a logger for a component."""
        if component not in self._loggers:
            self._loggers[component] = ComponentLogger(self, component)
        return self._loggers[component]

    def should_log(self, level: DebugLevel, component: str) -> bool:
        """Check if a message should be logged."""
        if level > self.config.level:
            return False

        # If components filter is set, check it
        if self.config.components and component not in self.config.components:
            return False

        return True

    def emit(self, level: DebugLevel, component: str, message: str, **extra):
        """Emit a debug message to all channels."""
        if not self.should_log(level, component):
            return

        elapsed = time.monotonic() - self._start_time
        timestamp = time.strftime("%H:%M:%S")

        # Build log record
        record = {
            "ts": timestamp,
            "elapsed": f"{elapsed:.3f}",
            "level": level.name,
            "component": component,
            "msg": message,
            **extra,
        }

        # Output to journald (structured JSON)
        self._emit_journald(record)

        # Output to console (colored)
        if self.config.enable_console:
            self._emit_console(record, level)

        # Output to FIFO
        if self._fifo_fd is not None:
            self._emit_fifo(record)

    def _emit_journald(self, record: dict):
        """Emit to systemd journal."""
        # Print as JSON line to stderr (captured by journald)
        try:
            print(json.dumps(record), file=sys.stderr)
        except Exception:
            pass

    def _emit_console(self, record: dict, level: DebugLevel):
        """Emit colored output to console."""
        colors = {
            DebugLevel.ERROR: Colors.RED,
            DebugLevel.WARN: Colors.YELLOW,
            DebugLevel.INFO: Colors.GREEN,
            DebugLevel.DEBUG: Colors.CYAN,
            DebugLevel.TRACE: Colors.GRAY,
        }

        color = colors.get(level, Colors.RESET)
        comp = record["component"][:8].ljust(8)

        line = (
            f"{Colors.GRAY}[{record['elapsed']}]{Colors.RESET} "
            f"{color}{record['level'][:4]}{Colors.RESET} "
            f"{Colors.MAGENTA}{comp}{Colors.RESET} "
            f"{record['msg']}"
        )

        try:
            print(line, file=sys.stderr)
        except Exception:
            pass

    def _emit_fifo(self, record: dict):
        """Emit to debug FIFO."""
        if self._fifo_fd is None:
            return

        try:
            line = json.dumps(record) + "\n"
            os.write(self._fifo_fd, line.encode("utf-8"))
        except (OSError, IOError):
            # FIFO not readable, ignore
            pass

    def set_level(self, level: DebugLevel):
        """Change debug level at runtime."""
        self.config.level = level

    def add_component(self, component: str):
        """Add a component to the filter."""
        self.config.components.add(component)

    def clear_components(self):
        """Clear component filter (log all)."""
        self.config.components.clear()


class ComponentLogger:
    """Logger for a specific component."""

    def __init__(self, manager: DebugManager, component: str):
        self._manager = manager
        self._component = component

    def error(self, msg: str, *args, **kwargs):
        """Log an error message."""
        self._log(DebugLevel.ERROR, msg, *args, **kwargs)

    def warn(self, msg: str, *args, **kwargs):
        """Log a warning message."""
        self._log(DebugLevel.WARN, msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        """Log an info message."""
        self._log(DebugLevel.INFO, msg, *args, **kwargs)

    def debug(self, msg: str, *args, **kwargs):
        """Log a debug message."""
        self._log(DebugLevel.DEBUG, msg, *args, **kwargs)

    def trace(self, msg: str, *args, **kwargs):
        """Log a trace message."""
        self._log(DebugLevel.TRACE, msg, *args, **kwargs)

    def _log(self, level: DebugLevel, msg: str, *args, **kwargs):
        """Internal log method."""
        if args:
            try:
                msg = msg % args
            except TypeError:
                pass

        self._manager.emit(level, self._component, msg, **kwargs)


# Module-level convenience functions
_default_manager: Optional[DebugManager] = None


def get_logger(component: str) -> ComponentLogger:
    """Get a logger for a component."""
    global _default_manager
    if _default_manager is None:
        _default_manager = DebugManager()
    return _default_manager.get_logger(component)


def set_debug_level(level: int):
    """Set global debug level."""
    global _default_manager
    if _default_manager is None:
        _default_manager = DebugManager()
    _default_manager.set_level(DebugLevel(level))
