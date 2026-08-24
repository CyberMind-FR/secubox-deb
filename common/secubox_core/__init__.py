# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
secubox_core — Bibliothèque partagée SecuBox-DEB
================================================
JWT auth · Config TOML · Logging structuré · Helpers système · Kiosk/Board
"""
__version__ = "1.1.0"

from .auth   import require_jwt, create_token, router as auth_router
from .config import get_config, get_board_info, reload_config
from .logger import get_logger
from .system import (
    board_info, uptime, service_status, service_control,
    disk_usage, load_average,
)
from .kiosk import (
    kiosk_status, kiosk_enable, kiosk_disable,
    console_status, display_mode,
    detect_board_type, get_board_profile, get_board_capabilities, get_board_model,
    get_physical_interfaces, get_interface_classification, check_interface_carrier,
)
from .health import (
    WorkingStatus, EnabledStatus, DevStage,
    HealthResponse, make_health_response, health_from_checks,
    MODULE_METADATA, get_module_metadata,
    parse_units, systemd_batch,
)

__all__ = [
    # Auth
    "require_jwt", "create_token", "auth_router",
    # Config
    "get_config", "get_board_info", "reload_config",
    # Logger
    "get_logger",
    # System
    "board_info", "uptime", "service_status", "service_control",
    "disk_usage", "load_average",
    # Kiosk & Board Detection
    "kiosk_status", "kiosk_enable", "kiosk_disable",
    "console_status", "display_mode",
    "detect_board_type", "get_board_profile", "get_board_capabilities", "get_board_model",
    "get_physical_interfaces", "get_interface_classification", "check_interface_carrier",
    # Health
    "WorkingStatus", "EnabledStatus", "DevStage",
    "HealthResponse", "make_health_response", "health_from_checks",
    "MODULE_METADATA", "get_module_metadata",
    "parse_units", "systemd_batch",
]
