"""
SecuBox Eye Remote Agent
Manages connections to SecuBox appliances and feeds metrics to dashboard.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
__version__ = "2.0.0"

from .command_handler import (
    Command,
    CommandHandler,
    WebSocketClient,
    create_command_client,
    capture_screenshot,
)

__all__ = [
    "Command",
    "CommandHandler",
    "WebSocketClient",
    "create_command_client",
    "capture_screenshot",
]
