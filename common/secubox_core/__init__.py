"""
secubox_core — Bibliothèque partagée SecuBox-DEB
================================================
JWT auth · Config TOML · Logging structuré · Helpers système
"""
__version__ = "1.0.0"

from .auth   import require_jwt, create_token, router as auth_router
from .config import get_config, get_board_info, reload_config
from .logger import get_logger
from .system import (
    board_info, uptime, service_status, service_control,
    disk_usage, load_average,
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
]
