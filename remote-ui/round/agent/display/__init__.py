# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Display rendering modules for Eye Remote.

The display system uses a manager-based architecture:
- display_manager.py: Main controller that manages display priority
- fallback/fallback_manager.py: Main dashboard renderer
- logo_fallback.py: Endless fallback logo display
- firstboot_sensor.py: First boot setup screen
- splash.py: Splash screen
- gadget_status.py: USB gadget status overlay
- setup_wizard.py: Self-setup portal wizard display
- renderers.py: Mode-specific renderers (Dashboard, Local, Flash, Gateway)

Entry point: Run display_manager.py directly via systemd.
"""

import logging

log = logging.getLogger(__name__)

# Core exports that should always work
__all__ = []

# Display manager - core component
try:
    from .display_manager import DisplayManager, DisplayMode
    __all__.extend(['DisplayManager', 'DisplayMode'])
except ImportError as e:
    log.warning(f"Could not import display_manager: {e}")
    DisplayManager = None
    DisplayMode = None

# Gadget status renderer
try:
    from .gadget_status import (
        GadgetStatusRenderer,
        get_renderer as get_gadget_renderer,
        render_gadget_status_bar,
        render_gadget_full_status,
        render_gadget_indicator,
    )
    __all__.extend([
        'GadgetStatusRenderer',
        'get_gadget_renderer',
        'render_gadget_status_bar',
        'render_gadget_full_status',
        'render_gadget_indicator',
    ])
except ImportError as e:
    log.warning(f"Could not import gadget_status: {e}")
    GadgetStatusRenderer = None
    get_gadget_renderer = None
    render_gadget_status_bar = None
    render_gadget_full_status = None
    render_gadget_indicator = None

# Gadget gesture handling
try:
    from .gadget_gesture import (
        GadgetGestureHandler,
        get_gesture_handler,
        GestureState,
        GestureResult,
    )
    __all__.extend([
        'GadgetGestureHandler',
        'get_gesture_handler',
        'GestureState',
        'GestureResult',
    ])
except ImportError as e:
    log.warning(f"Could not import gadget_gesture: {e}")
    GadgetGestureHandler = None
    get_gesture_handler = None
    GestureState = None
    GestureResult = None

# Setup wizard (has external dependencies)
try:
    from .setup_wizard import (
        SetupWizardDisplay,
        get_wizard_display,
        TouchAction,
    )
    __all__.extend([
        'SetupWizardDisplay',
        'get_wizard_display',
        'TouchAction',
    ])
except ImportError as e:
    log.debug(f"Could not import setup_wizard (optional): {e}")
    SetupWizardDisplay = None
    get_wizard_display = None
    TouchAction = None

# Mode-specific renderers
try:
    from .renderers import (
        RenderContext,
        BaseRenderer,
        DashboardRenderer,
        LocalRenderer,
        FlashRenderer,
        GatewayRenderer,
    )
    __all__.extend([
        'RenderContext',
        'BaseRenderer',
        'DashboardRenderer',
        'LocalRenderer',
        'FlashRenderer',
        'GatewayRenderer',
    ])
except ImportError as e:
    log.warning(f"Could not import renderers: {e}")
    RenderContext = None
    BaseRenderer = None
    DashboardRenderer = None
    LocalRenderer = None
    FlashRenderer = None
    GatewayRenderer = None
