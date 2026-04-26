"""
SecuBox Eye Remote — Web Remote Server
FastAPI-based web server for remote control of Eye Remote device.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from .server import create_app, WebServer
from .websocket import (
    ConnectionManager,
    MessageType,
    create_message,
    mode_changed_message,
    metrics_update_message,
    alert_message,
    device_status_message,
    connection_status_message,
)

__all__ = [
    'create_app',
    'WebServer',
    'ConnectionManager',
    'MessageType',
    'create_message',
    'mode_changed_message',
    'metrics_update_message',
    'alert_message',
    'device_status_message',
    'connection_status_message',
]
