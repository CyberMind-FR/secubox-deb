"""
SecuBox Eye Remote — WebSocket Tests
Tests for WebSocket connection manager and real-time updates.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from agent.web.websocket import (
    ConnectionManager,
    MessageType,
    create_message,
    mode_changed_message,
    metrics_update_message,
    alert_message,
    device_status_message,
    connection_status_message,
)


# --- ConnectionManager Tests ---

def test_connection_manager_init():
    """ConnectionManager should initialize with zero connections."""
    manager = ConnectionManager()
    assert manager.connection_count == 0
    assert manager.has_connections is False


@pytest.mark.asyncio
async def test_connection_manager_connect():
    """ConnectionManager should track connected websockets."""
    manager = ConnectionManager()

    # Mock websocket
    mock_ws = AsyncMock()
    mock_ws.accept = AsyncMock()

    await manager.connect(mock_ws)

    assert manager.connection_count == 1
    assert manager.has_connections is True
    mock_ws.accept.assert_called_once()


@pytest.mark.asyncio
async def test_connection_manager_disconnect():
    """ConnectionManager should remove disconnected websockets."""
    manager = ConnectionManager()

    # Connect a websocket
    mock_ws = AsyncMock()
    mock_ws.accept = AsyncMock()
    await manager.connect(mock_ws)
    assert manager.connection_count == 1

    # Disconnect
    await manager.disconnect(mock_ws)
    assert manager.connection_count == 0
    assert manager.has_connections is False


@pytest.mark.asyncio
async def test_connection_manager_disconnect_not_connected():
    """ConnectionManager disconnect should handle non-existent connections."""
    manager = ConnectionManager()
    mock_ws = AsyncMock()

    # Should not raise
    await manager.disconnect(mock_ws)
    assert manager.connection_count == 0


@pytest.mark.asyncio
async def test_connection_manager_broadcast_empty():
    """Broadcast should handle no connections gracefully."""
    manager = ConnectionManager()

    # Should not raise
    await manager.broadcast({"type": "test"})


@pytest.mark.asyncio
async def test_connection_manager_broadcast():
    """Broadcast should send to all connected clients."""
    manager = ConnectionManager()

    # Connect multiple websockets
    mock_ws1 = AsyncMock()
    mock_ws1.accept = AsyncMock()
    mock_ws1.send_text = AsyncMock()

    mock_ws2 = AsyncMock()
    mock_ws2.accept = AsyncMock()
    mock_ws2.send_text = AsyncMock()

    await manager.connect(mock_ws1)
    await manager.connect(mock_ws2)

    # Broadcast
    message = {"type": "test", "data": "hello"}
    await manager.broadcast(message)

    # Both should receive
    import json
    expected = json.dumps(message)
    mock_ws1.send_text.assert_called_once_with(expected)
    mock_ws2.send_text.assert_called_once_with(expected)


@pytest.mark.asyncio
async def test_connection_manager_broadcast_removes_dead():
    """Broadcast should clean up dead connections."""
    manager = ConnectionManager()

    # One good, one dead
    mock_ws_good = AsyncMock()
    mock_ws_good.accept = AsyncMock()
    mock_ws_good.send_text = AsyncMock()

    mock_ws_dead = AsyncMock()
    mock_ws_dead.accept = AsyncMock()
    mock_ws_dead.send_text = AsyncMock(side_effect=Exception("Connection closed"))

    await manager.connect(mock_ws_good)
    await manager.connect(mock_ws_dead)
    assert manager.connection_count == 2

    # Broadcast - dead connection should be cleaned up
    await manager.broadcast({"type": "test"})

    assert manager.connection_count == 1


@pytest.mark.asyncio
async def test_connection_manager_send_to():
    """send_to should send to specific client."""
    manager = ConnectionManager()

    mock_ws = AsyncMock()
    mock_ws.send_text = AsyncMock()

    message = {"type": "test"}
    result = await manager.send_to(mock_ws, message)

    assert result is True
    import json
    mock_ws.send_text.assert_called_once_with(json.dumps(message))


@pytest.mark.asyncio
async def test_connection_manager_send_to_failure():
    """send_to should return False on failure."""
    manager = ConnectionManager()

    mock_ws = AsyncMock()
    mock_ws.send_text = AsyncMock(side_effect=Exception("Send failed"))

    result = await manager.send_to(mock_ws, {"type": "test"})

    assert result is False


# --- MessageType Tests ---

def test_message_type_constants():
    """MessageType should have expected constants."""
    assert MessageType.MODE_CHANGED == "mode_changed"
    assert MessageType.METRICS_UPDATE == "metrics_update"
    assert MessageType.ALERT == "alert"
    assert MessageType.DEVICE_STATUS == "device_status"
    assert MessageType.CONNECTION_STATUS == "connection_status"
    assert MessageType.PING == "ping"
    assert MessageType.PONG == "pong"


# --- create_message Tests ---

def test_create_message():
    """create_message should create standardized message."""
    msg = create_message(MessageType.MODE_CHANGED, {"mode": "dashboard"})

    assert msg["type"] == "mode_changed"
    assert msg["data"]["mode"] == "dashboard"
    assert "timestamp" in msg
    assert isinstance(msg["timestamp"], float)


def test_create_message_with_source():
    """create_message should include source when provided."""
    msg = create_message(
        MessageType.ALERT,
        {"message": "Test"},
        source="test_module"
    )

    assert msg["source"] == "test_module"


def test_create_message_without_source():
    """create_message should not include source when not provided."""
    msg = create_message(MessageType.PING, {})

    assert "source" not in msg


# --- Convenience Function Tests ---

def test_mode_changed_message():
    """mode_changed_message should create proper message."""
    msg = mode_changed_message("dashboard", "local")

    assert msg["type"] == MessageType.MODE_CHANGED
    assert msg["data"]["mode"] == "dashboard"
    assert msg["data"]["previous_mode"] == "local"
    assert msg["source"] == "mode_manager"


def test_mode_changed_message_no_previous():
    """mode_changed_message should handle no previous mode."""
    msg = mode_changed_message("dashboard")

    assert msg["data"]["mode"] == "dashboard"
    assert msg["data"]["previous_mode"] is None


def test_metrics_update_message():
    """metrics_update_message should create proper message."""
    metrics = {"cpu_percent": 25.5, "mem_percent": 60.0}
    msg = metrics_update_message(metrics)

    assert msg["type"] == MessageType.METRICS_UPDATE
    assert msg["data"]["cpu_percent"] == 25.5
    assert msg["data"]["mem_percent"] == 60.0
    assert msg["source"] == "metrics_collector"


def test_alert_message():
    """alert_message should create proper message."""
    msg = alert_message("cpu_high", "CPU usage high", "warning", "system")

    assert msg["type"] == MessageType.ALERT
    assert msg["data"]["alert_type"] == "cpu_high"
    assert msg["data"]["message"] == "CPU usage high"
    assert msg["data"]["severity"] == "warning"
    assert msg["data"]["module"] == "system"
    assert msg["source"] == "alerts"


def test_alert_message_defaults():
    """alert_message should use default severity."""
    msg = alert_message("test", "Test message")

    assert msg["data"]["severity"] == "info"
    assert msg["data"]["module"] is None


def test_device_status_message():
    """device_status_message should create proper message."""
    msg = device_status_message("secubox-1", "connected")

    assert msg["type"] == MessageType.DEVICE_STATUS
    assert msg["data"]["device_id"] == "secubox-1"
    assert msg["data"]["status"] == "connected"
    assert msg["source"] == "device_manager"


def test_device_status_message_with_details():
    """device_status_message should include details."""
    details = {"ip": "10.55.0.1", "uptime": 3600}
    msg = device_status_message("secubox-1", "connected", details)

    assert msg["data"]["details"]["ip"] == "10.55.0.1"
    assert msg["data"]["details"]["uptime"] == 3600


def test_connection_status_message():
    """connection_status_message should create proper message."""
    msg = connection_status_message(True, "OTG")

    assert msg["type"] == MessageType.CONNECTION_STATUS
    assert msg["data"]["connected"] is True
    assert msg["data"]["transport"] == "OTG"
    assert msg["source"] == "connection"


def test_connection_status_message_disconnected():
    """connection_status_message should handle disconnected state."""
    msg = connection_status_message(False)

    assert msg["data"]["connected"] is False
    assert msg["data"]["transport"] is None


# --- WebSocket Endpoint Integration Tests ---

def test_websocket_connect():
    """WebSocket endpoint should accept connections."""
    from agent.web import create_app

    app = create_app()

    with TestClient(app) as client:
        with client.websocket_connect("/ws") as websocket:
            # First receive initial state
            initial = websocket.receive_json()
            assert initial["type"] == "initial_state"

            # Send ping
            websocket.send_json({"type": "ping"})

            # Should receive pong
            data = websocket.receive_json()
            assert data["type"] == "pong"


def test_websocket_invalid_json():
    """WebSocket endpoint should handle invalid JSON gracefully."""
    from agent.web import create_app

    app = create_app()

    with TestClient(app) as client:
        with client.websocket_connect("/ws") as websocket:
            # First receive initial state
            initial = websocket.receive_json()
            assert initial["type"] == "initial_state"

            # Send invalid JSON text
            websocket.send_text("not valid json")

            # Should receive error response
            data = websocket.receive_json()
            assert data["type"] == "error"


def test_websocket_unknown_message():
    """WebSocket endpoint should handle unknown message types."""
    from agent.web import create_app

    app = create_app()

    with TestClient(app) as client:
        with client.websocket_connect("/ws") as websocket:
            # First receive initial state
            initial = websocket.receive_json()
            assert initial["type"] == "initial_state"

            # Send unknown type
            websocket.send_json({"type": "unknown_type"})

            # Should receive acknowledgment
            data = websocket.receive_json()
            assert data["type"] == "ack"

            # Connection should still be alive
            websocket.send_json({"type": "ping"})
            data = websocket.receive_json()
            assert data["type"] == "pong"


def test_websocket_manager_in_app_state():
    """WebSocket manager should be available in app state."""
    from agent.web import create_app

    app = create_app()

    assert hasattr(app.state, 'ws_manager')
    assert isinstance(app.state.ws_manager, ConnectionManager)


def test_websocket_initial_state():
    """WebSocket endpoint should send initial state on connect."""
    from agent.web import create_app
    from agent.mode_manager import ModeManager, Mode

    mm = ModeManager(initial_mode=Mode.DASHBOARD)
    app = create_app(mode_manager=mm)

    with TestClient(app) as client:
        with client.websocket_connect("/ws") as websocket:
            # First message should be initial state
            data = websocket.receive_json()
            assert data["type"] in ["initial_state", "mode_changed", "connection_status"]


# --- Concurrent Connection Tests ---

def test_websocket_multiple_connections():
    """WebSocket endpoint should handle multiple connections."""
    from agent.web import create_app

    app = create_app()

    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws1:
            # First receive initial state for ws1
            initial1 = ws1.receive_json()
            assert initial1["type"] == "initial_state"

            with client.websocket_connect("/ws") as ws2:
                # First receive initial state for ws2
                initial2 = ws2.receive_json()
                assert initial2["type"] == "initial_state"

                # Both should work
                ws1.send_json({"type": "ping"})
                ws2.send_json({"type": "ping"})

                # Both should receive pong
                data1 = ws1.receive_json()
                data2 = ws2.receive_json()

                assert data1["type"] == "pong"
                assert data2["type"] == "pong"
