"""
SecuBox Eye Remote — System management modules
Provides system-level management functionality for the Eye Remote device.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from .wifi import WifiManager, WifiNetwork, WifiStatus

__all__ = ['WifiManager', 'WifiNetwork', 'WifiStatus']
