# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Console TUI Screens
"""
from .dashboard import DashboardScreen
from .services import ServicesScreen
from .network import NetworkScreen
from .logs import LogsScreen
from .menu import MenuScreen
from .soc_fleet import SOCFleetScreen
from .soc_alerts import SOCAlertsScreen
from .soc_node import SOCNodeScreen

__all__ = [
    "DashboardScreen",
    "ServicesScreen",
    "NetworkScreen",
    "LogsScreen",
    "MenuScreen",
    "SOCFleetScreen",
    "SOCAlertsScreen",
    "SOCNodeScreen",
]
