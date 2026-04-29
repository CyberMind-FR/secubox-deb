"""
SecuBox Eye Remote - API Module

Provides async metrics fetching from connected SecuBox devices
and USB gadget control.

CyberMind - https://cybermind.fr
"""

from .metrics_fetcher import (
    MetricsFetcher,
    SecuBoxMetrics,
    ConnectionState,
    get_fetcher,
    fetch_metrics,
    get_ring_values,
)

from .gadget import (
    GadgetController,
    GadgetStatus,
    GadgetMode,
    ConnectionState as GadgetConnectionState,
    get_controller,
    get_gadget_status,
    get_gadget_mode_info,
)

from .gadget_config import (
    GadgetConfig,
    EcmConfig,
    AcmConfig,
    MassStorageConfig,
    get_config as get_gadget_config,
    load_config as load_gadget_config,
    save_config as save_gadget_config,
    reload_config as reload_gadget_config,
)

from .gadget_switcher import (
    switch_mode,
    get_available_modes,
    get_current_mode,
    is_gadget_bound,
    SwitchResult,
    SwitchStatus,
)

from .setup import (
    SetupWizard,
    SetupStep,
    SetupStatus,
    StepStatus,
    SecuBoxInfo,
    NetworkConfig,
    SecurityConfig,
    ServicesConfig,
    MeshConfig,
    get_setup_wizard,
)

__all__ = [
    # Metrics
    'MetricsFetcher',
    'SecuBoxMetrics',
    'ConnectionState',
    'get_fetcher',
    'fetch_metrics',
    'get_ring_values',
    # Gadget status
    'GadgetController',
    'GadgetStatus',
    'GadgetMode',
    'GadgetConnectionState',
    'get_controller',
    'get_gadget_status',
    'get_gadget_mode_info',
    # Gadget config
    'GadgetConfig',
    'EcmConfig',
    'AcmConfig',
    'MassStorageConfig',
    'get_gadget_config',
    'load_gadget_config',
    'save_gadget_config',
    'reload_gadget_config',
    # Gadget switcher
    'switch_mode',
    'get_available_modes',
    'get_current_mode',
    'is_gadget_bound',
    'SwitchResult',
    'SwitchStatus',
    # Setup wizard
    'SetupWizard',
    'SetupStep',
    'SetupStatus',
    'StepStatus',
    'SecuBoxInfo',
    'NetworkConfig',
    'SecurityConfig',
    'ServicesConfig',
    'MeshConfig',
    'get_setup_wizard',
]
