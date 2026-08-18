# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox UI Manager - Core Library
"""

from .debug import get_logger, DebugLevel, DebugManager
from .state_machine import UIStateMachine, UIState
from .hypervisor import HypervisorDetector, HypervisorInfo, GraphicsConfig
from .display import DisplayDetector, DisplayInfo
from .fallback import FallbackChain, FallbackConfig
from .health import HealthMonitor, HealthStatus

__all__ = [
    "get_logger",
    "DebugLevel",
    "DebugManager",
    "UIStateMachine",
    "UIState",
    "HypervisorDetector",
    "HypervisorInfo",
    "GraphicsConfig",
    "DisplayDetector",
    "DisplayInfo",
    "FallbackChain",
    "FallbackConfig",
    "HealthMonitor",
    "HealthStatus",
]
