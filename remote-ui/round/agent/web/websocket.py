"""
SecuBox Eye Remote — WebSocket Support
WebSocket connection manager for real-time updates to connected clients.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Set, Dict, Any, Optional

from fastapi import WebSocket, WebSocketDisconnect

log = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections for real-time updates.

    Thread-safe connection tracking with broadcast capabilities.
    Automatically cleans up dead connections on broadcast.
    """

    def __init__(self):
        """Initialize connection manager with empty connection set."""
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """
        Accept and track a new WebSocket connection.

        Args:
            websocket: The WebSocket connection to accept and track
        """
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        log.info(f"WebSocket client connected. Total: {len(self._connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Remove a WebSocket connection from tracking.

        Args:
            websocket: The WebSocket connection to remove
        """
        async with self._lock:
            self._connections.discard(websocket)
        log.info(f"WebSocket client disconnected. Total: {len(self._connections)}")

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """
        Send message to all connected clients.

        Automatically removes dead connections on send failure.

        Args:
            message: Dictionary to broadcast as JSON
        """
        if not self._connections:
            return

        data = json.dumps(message)
        async with self._lock:
            dead_connections: Set[WebSocket] = set()
            for websocket in self._connections:
                try:
                    await websocket.send_text(data)
                except Exception as e:
                    log.debug(f"Failed to send to client, marking as dead: {e}")
                    dead_connections.add(websocket)

            # Clean up dead connections
            if dead_connections:
                self._connections -= dead_connections
                log.info(f"Cleaned up {len(dead_connections)} dead connections")

    async def send_to(self, websocket: WebSocket, message: Dict[str, Any]) -> bool:
        """
        Send message to specific client.

        Args:
            websocket: Target WebSocket connection
            message: Dictionary to send as JSON

        Returns:
            True if message sent successfully, False otherwise
        """
        try:
            await websocket.send_text(json.dumps(message))
            return True
        except Exception as e:
            log.error(f"Failed to send to client: {e}")
            return False

    @property
    def connection_count(self) -> int:
        """
        Number of active connections.

        Returns:
            Count of tracked WebSocket connections
        """
        return len(self._connections)

    @property
    def has_connections(self) -> bool:
        """
        Check if any clients are connected.

        Returns:
            True if at least one connection exists
        """
        return len(self._connections) > 0


class MessageType:
    """Standard WebSocket message types for Eye Remote."""

    # Mode changes
    MODE_CHANGED = "mode_changed"
    MODE_CHANGING = "mode_changing"

    # Real-time metrics
    METRICS_UPDATE = "metrics_update"

    # Alert notifications
    ALERT = "alert"
    ALERT_CLEARED = "alert_cleared"

    # Device status
    DEVICE_STATUS = "device_status"
    DEVICE_CONNECTED = "device_connected"
    DEVICE_DISCONNECTED = "device_disconnected"

    # Connection status
    CONNECTION_STATUS = "connection_status"

    # System events
    SYSTEM_EVENT = "system_event"

    # Ping/pong for keepalive
    PING = "ping"
    PONG = "pong"


def create_message(
    msg_type: str,
    data: Dict[str, Any],
    source: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a standardized WebSocket message.

    Args:
        msg_type: Message type from MessageType class
        data: Message payload data
        source: Optional source identifier

    Returns:
        Formatted message dictionary with type, data, and timestamp
    """
    message = {
        "type": msg_type,
        "data": data,
        "timestamp": time.time(),
    }
    if source:
        message["source"] = source
    return message


# Convenience functions for common message types

def mode_changed_message(
    new_mode: str,
    previous_mode: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a mode change notification message.

    Args:
        new_mode: The new mode name
        previous_mode: The previous mode name

    Returns:
        Formatted mode change message
    """
    return create_message(
        MessageType.MODE_CHANGED,
        {
            "mode": new_mode,
            "previous_mode": previous_mode,
        },
        source="mode_manager"
    )


def metrics_update_message(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a metrics update message.

    Args:
        metrics: Dictionary of current metrics

    Returns:
        Formatted metrics message
    """
    return create_message(
        MessageType.METRICS_UPDATE,
        metrics,
        source="metrics_collector"
    )


def alert_message(
    alert_type: str,
    message: str,
    severity: str = "info",
    module: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create an alert notification message.

    Args:
        alert_type: Type of alert
        message: Alert message text
        severity: Alert severity (info, warning, critical)
        module: Module that generated the alert

    Returns:
        Formatted alert message
    """
    return create_message(
        MessageType.ALERT,
        {
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
            "module": module,
        },
        source="alerts"
    )


def device_status_message(
    device_id: str,
    status: str,
    details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Create a device status update message.

    Args:
        device_id: Device identifier
        status: Device status string
        details: Optional additional details

    Returns:
        Formatted device status message
    """
    data = {
        "device_id": device_id,
        "status": status,
    }
    if details:
        data["details"] = details
    return create_message(
        MessageType.DEVICE_STATUS,
        data,
        source="device_manager"
    )


def connection_status_message(
    connected: bool,
    transport: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a connection status message.

    Args:
        connected: Whether connection is active
        transport: Transport type (OTG, WiFi, etc.)

    Returns:
        Formatted connection status message
    """
    return create_message(
        MessageType.CONNECTION_STATUS,
        {
            "connected": connected,
            "transport": transport,
        },
        source="connection"
    )
