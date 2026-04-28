#!/usr/bin/env python3
"""
SecuBox Eye Remote - Fallback Display Mode
Activates local radar visualization when OTG/WiFi connection unavailable.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

from .fallback_manager import FallbackManager, FallbackMode

__all__ = ['FallbackManager', 'FallbackMode']
