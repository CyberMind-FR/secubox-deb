# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote — System management modules
Provides system-level management functionality for the Eye Remote device.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from .wifi import WifiManager, WifiNetwork, WifiStatus
from .bluetooth import BluetoothManager, BluetoothDevice, BluetoothStatus
from .display_control import DisplayController, DisplayStatus

__all__ = [
    'WifiManager',
    'WifiNetwork',
    'WifiStatus',
    'BluetoothManager',
    'BluetoothDevice',
    'BluetoothStatus',
    'DisplayController',
    'DisplayStatus',
]
