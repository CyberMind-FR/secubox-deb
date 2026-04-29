"""Display rendering modules for Eye Remote.

The display system uses a manager-based architecture:
- display_manager.py: Main controller that manages display priority
- fallback/fallback_manager.py: Main dashboard renderer
- logo_fallback.py: Endless fallback logo display
- firstboot_sensor.py: First boot setup screen
- splash.py: Splash screen
- gadget_status.py: USB gadget status overlay
- setup_wizard.py: Self-setup portal wizard display

Entry point: Run display_manager.py directly via systemd.
"""

# Export the manager classes that actually exist
from .display_manager import DisplayManager, DisplayMode
from .gadget_status import (
    GadgetStatusRenderer,
    get_renderer as get_gadget_renderer,
    render_gadget_status_bar,
    render_gadget_full_status,
    render_gadget_indicator,
)

from .gadget_gesture import (
    GadgetGestureHandler,
    get_gesture_handler,
    GestureState,
    GestureResult,
)

from .setup_wizard import (
    SetupWizardDisplay,
    get_wizard_display,
    TouchAction,
)

__all__ = [
    'DisplayManager',
    'DisplayMode',
    'GadgetStatusRenderer',
    'get_gadget_renderer',
    'render_gadget_status_bar',
    'render_gadget_full_status',
    'render_gadget_indicator',
    'GadgetGestureHandler',
    'get_gesture_handler',
    'GestureState',
    'GestureResult',
    'SetupWizardDisplay',
    'get_wizard_display',
    'TouchAction',
]
