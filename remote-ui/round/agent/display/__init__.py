"""Display rendering modules for Eye Remote.

The display system uses a manager-based architecture:
- display_manager.py: Main controller that manages display priority
- fallback/fallback_manager.py: Main dashboard renderer
- logo_fallback.py: Endless fallback logo display
- firstboot_sensor.py: First boot setup screen
- splash.py: Splash screen

Entry point: Run display_manager.py directly via systemd.
"""

# Export the manager classes that actually exist
from .display_manager import DisplayManager, DisplayMode

__all__ = [
    'DisplayManager',
    'DisplayMode',
]
