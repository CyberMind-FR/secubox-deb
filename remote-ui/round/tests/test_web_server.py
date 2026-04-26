"""
SecuBox Eye Remote — Web Server Tests
Tests for FastAPI web server and routes.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from agent.mode_manager import Mode, ModeManager
from agent.web import create_app, WebServer


# --- App Factory Tests ---

def test_create_app():
    """create_app should return FastAPI app."""
    app = create_app()
    assert app is not None
    assert hasattr(app, 'routes')


def test_create_app_with_mode_manager():
    """create_app should accept mode_manager parameter."""
    mm = ModeManager()
    app = create_app(mode_manager=mm)
    assert app.state.mode_manager is mm


def test_create_app_with_config():
    """create_app should accept config parameter."""
    from agent.config import Config
    config = Config()
    app = create_app(config=config)
    assert app.state.config is config


# --- Health Endpoint Tests ---

def test_health_endpoint():
    """Health endpoint should return OK."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "eye-remote-web"


# --- Control Page Tests ---

def test_control_page_returns_html():
    """Control page should serve HTML content."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/control")

    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "Eye Remote" in response.text


# --- Mode Route Tests ---

def test_mode_get_without_manager():
    """GET /mode should return error when no mode manager."""
    app = create_app(mode_manager=None)
    client = TestClient(app)
    response = client.get("/api/mode")

    assert response.status_code == 503
    data = response.json()
    assert "unavailable" in data.get("detail", "").lower()


def test_mode_get_with_manager():
    """GET /mode should return current mode."""
    mm = ModeManager(initial_mode=Mode.DASHBOARD)
    app = create_app(mode_manager=mm)
    client = TestClient(app)
    response = client.get("/api/mode")

    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "dashboard"
    assert data["previous_mode"] is None


def test_mode_post_change():
    """POST /mode should change mode."""
    mm = ModeManager(initial_mode=Mode.LOCAL)
    app = create_app(mode_manager=mm)
    client = TestClient(app)
    response = client.post("/api/mode", json={"mode": "dashboard"})

    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "dashboard"
    assert data["changed"] is True


def test_mode_post_invalid():
    """POST /mode should reject invalid mode."""
    mm = ModeManager()
    app = create_app(mode_manager=mm)
    client = TestClient(app)
    response = client.post("/api/mode", json={"mode": "invalid_mode"})

    assert response.status_code == 400
    data = response.json()
    assert "invalid" in data.get("detail", "").lower()


def test_mode_post_same_mode():
    """POST /mode with same mode should indicate no change."""
    mm = ModeManager(initial_mode=Mode.DASHBOARD)
    app = create_app(mode_manager=mm)
    client = TestClient(app)
    response = client.post("/api/mode", json={"mode": "dashboard"})

    assert response.status_code == 200
    data = response.json()
    assert data["changed"] is False


# --- WiFi Route Tests ---

def test_wifi_status_endpoint():
    """GET /wifi/status should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/wifi/status")

    assert response.status_code == 200
    data = response.json()
    assert "connected" in data


def test_wifi_networks_endpoint():
    """GET /wifi/networks should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/wifi/networks")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data.get("networks"), list)


# --- Bluetooth Route Tests ---

def test_bluetooth_status_endpoint():
    """GET /bluetooth/status should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/bluetooth/status")

    assert response.status_code == 200
    data = response.json()
    assert "enabled" in data


def test_bluetooth_devices_endpoint():
    """GET /bluetooth/devices should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/bluetooth/devices")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data.get("devices"), list)


# --- Display Route Tests ---

def test_display_settings_endpoint():
    """GET /display/settings should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/display/settings")

    assert response.status_code == 200
    data = response.json()
    assert "brightness" in data


def test_display_brightness_post():
    """POST /display/brightness should accept value."""
    app = create_app()
    client = TestClient(app)
    response = client.post("/api/display/brightness", json={"value": 80})

    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True


# --- Devices Route Tests ---

def test_devices_list_endpoint():
    """GET /devices should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/devices")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data.get("devices"), list)


def test_devices_scan_endpoint():
    """POST /devices/scan should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.post("/api/devices/scan")

    assert response.status_code == 200
    data = response.json()
    assert "status" in data


# --- System Route Tests ---

def test_system_info_endpoint():
    """GET /system/info should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/system/info")

    assert response.status_code == 200
    data = response.json()
    assert "hostname" in data


def test_system_reboot_endpoint():
    """POST /system/reboot should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.post("/api/system/reboot")

    assert response.status_code == 200
    data = response.json()
    assert "status" in data


# --- SecuBox Route Tests ---

def test_secubox_status_endpoint():
    """GET /secubox/status should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/secubox/status")

    assert response.status_code == 200
    data = response.json()
    assert "connected" in data


def test_secubox_metrics_endpoint():
    """GET /secubox/metrics should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/secubox/metrics")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)


def test_secubox_modules_endpoint():
    """GET /secubox/modules should return stub response."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/secubox/modules")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data.get("modules"), list)


# --- WebServer Class Tests ---

def test_webserver_init():
    """WebServer should initialize with default values."""
    server = WebServer()
    assert server.host == "0.0.0.0"
    assert server.port == 8080


def test_webserver_init_custom_values():
    """WebServer should accept custom host and port."""
    server = WebServer(host="127.0.0.1", port=9000)
    assert server.host == "127.0.0.1"
    assert server.port == 9000


def test_webserver_has_app():
    """WebServer should have app attribute."""
    server = WebServer()
    assert server.app is not None


@pytest.mark.asyncio
async def test_webserver_start_stop():
    """WebServer should have start and stop methods."""
    server = WebServer()
    # Just verify methods exist and are callable
    assert hasattr(server, 'start')
    assert hasattr(server, 'stop')
    assert callable(server.start)
    assert callable(server.stop)


# --- Route Registration Tests ---

def test_all_routes_registered():
    """All expected routes should be registered."""
    app = create_app()

    # Get all registered paths
    routes = [route.path for route in app.routes]

    # Check key routes are present
    assert "/api/health" in routes
    assert "/control" in routes
    assert "/api/mode" in routes
    # WiFi, Bluetooth, Display, Devices, System, SecuBox routes
    # are registered under their prefixes


def test_mode_routes_registered():
    """Mode routes should be accessible."""
    app = create_app()
    client = TestClient(app)

    # GET and POST on /api/mode should work
    response = client.get("/api/mode")
    assert response.status_code in [200, 503]  # Depends on mode_manager

    response = client.post("/api/mode", json={"mode": "local"})
    assert response.status_code in [200, 400, 503]
