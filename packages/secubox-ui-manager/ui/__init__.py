"""
SecuBox UI Manager
==================

Unified interface manager for SecuBox with three modes:
- KUI: Kiosk UI (X11/Chromium fullscreen)
- TUI: Terminal UI (Textual-based console)
- Console: Standard shell login

Features:
- Automatic hypervisor detection and optimization
- Graceful fallback chain (KUI → TUI → Console)
- Modular debug system with levels 0-5
- Health monitoring and auto-recovery

Usage:
    from ui import UIManager
    manager = UIManager()
    await manager.run()

CLI:
    secubox-ui-manager [--mode kui|tui|console] [--debug LEVEL]

Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate
"""

__version__ = "1.0.0"
__author__ = "Gerald KERMA"

from .lib.debug import get_logger, set_debug_level, DebugLevel, DebugManager
from .lib.state_machine import UIStateMachine, UIState
from .lib.hypervisor import HypervisorDetector, HypervisorInfo, GraphicsConfig
from .lib.display import DisplayDetector, DisplayInfo
from .lib.fallback import FallbackChain, FallbackConfig
from .lib.health import HealthMonitor, HealthStatus

from .drivers.kui_driver import KUIDriver
from .drivers.tui_driver import TUIDriver
from .drivers.console_driver import ConsoleDriver

from .manager import UIManager

__all__ = [
    # Version
    "__version__",
    # Manager
    "UIManager",
    # Debug
    "get_logger",
    "set_debug_level",
    "DebugLevel",
    "DebugManager",
    # State Machine
    "UIStateMachine",
    "UIState",
    # Detection
    "HypervisorDetector",
    "HypervisorInfo",
    "GraphicsConfig",
    "DisplayDetector",
    "DisplayInfo",
    # Fallback
    "FallbackChain",
    "FallbackConfig",
    # Health
    "HealthMonitor",
    "HealthStatus",
    # Drivers
    "KUIDriver",
    "TUIDriver",
    "ConsoleDriver",
]
