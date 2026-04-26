"""
SecuBox Eye Remote — Web Routes
API route modules for Eye Remote web server.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from . import mode
from . import wifi
from . import bluetooth
from . import display
from . import devices
from . import system
from . import secubox

__all__ = [
    'mode',
    'wifi',
    'bluetooth',
    'display',
    'devices',
    'system',
    'secubox',
]
