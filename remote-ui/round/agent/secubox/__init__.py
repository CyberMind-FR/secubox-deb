# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote — SecuBox Device Management Modules
Provides fleet management, device discovery, and remote control capabilities.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from .device_manager import ConnectionState, DeviceManager, SecuBoxDevice
from .fleet import DeviceStatus, FleetAggregator, FleetMetrics
from .remote_control import (
    SecuBoxAlert,
    SecuBoxClient,
    SecuBoxMetrics,
    SecuBoxModule,
)

__all__ = [
    # Device Manager
    "DeviceManager",
    "SecuBoxDevice",
    "ConnectionState",
    # Fleet Aggregator
    "FleetAggregator",
    "FleetMetrics",
    "DeviceStatus",
    # Remote Control
    "SecuBoxClient",
    "SecuBoxMetrics",
    "SecuBoxModule",
    "SecuBoxAlert",
]
