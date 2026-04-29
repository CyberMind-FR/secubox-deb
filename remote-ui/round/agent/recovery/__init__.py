"""
SecuBox Eye Remote — Recovery Module
Board recovery via kwboot, XMODEM, mvebu64boot, and Tow-Boot UEFI installation.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Supported protocols:
- kwboot: Marvell Kirkwood/Armada 3720 serial boot
- mvebu64boot: Marvell Armada 7040/8040 64-bit serial boot
- XMODEM: Standard file transfer for BootROM
"""
from .recovery_controller import RecoveryController, RecoveryState, BoardType, RecoveryMethod
from .protocols import KwbootProtocol, XmodemProtocol, Mvebu64Protocol

__all__ = [
    "RecoveryController",
    "RecoveryState",
    "RecoveryMethod",
    "BoardType",
    "KwbootProtocol",
    "XmodemProtocol",
    "Mvebu64Protocol",
]
