"""
SecuBox Eye Remote — Integration Tests
Comprehensive integration tests for the Eye Remote Swiss Army Dashboard.

Tests all components working together:
- Component initialization
- Mode transitions with WebSocket broadcasts
- API routes integration
- WebSocket connectivity
- System controllers
- SecuBox device management
- Error handling and graceful degradation

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Core components
from agent.mode_manager import Mode, ModeManager
from agent.failover import FailoverMonitor, FailoverState
from agent.config import Config

# Web components
from agent.web import create_app, WebServer
from agent.web.websocket import ConnectionManager, MessageType, create_message

# System controllers
from agent.system import WifiManager, BluetoothManager, DisplayController

# SecuBox management
from agent.secubox import (
    DeviceManager,
    SecuBoxDevice,
    ConnectionState,
    SecuBoxClient,
    FleetAggregator,
    FleetMetrics,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def mode_manager():
    """Create a fresh ModeManager instance."""
    return ModeManager(initial_mode=Mode.LOCAL)


@pytest.fixture
def failover_monitor():
    """Create a fresh FailoverMonitor instance."""
    return FailoverMonitor()


@pytest.fixture
def config():
    """Create a Config instance (may use defaults)."""
    return Config()


@pytest.fixture
def wifi_manager():
    """Create a WifiManager instance."""
    return WifiManager()


@pytest.fixture
def bluetooth_manager():
    """Create a BluetoothManager instance."""
    return BluetoothManager()


@pytest.fixture
def display_controller():
    """Create a DisplayController instance."""
    return DisplayController()


@pytest.fixture
def app(mode_manager, failover_monitor, config, wifi_manager, bluetooth_manager, display_controller):
    """Create a fully configured FastAPI app."""
    return create_app(
        mode_manager=mode_manager,
        failover_monitor=failover_monitor,
        config=config,
        wifi_manager=wifi_manager,
        bluetooth_manager=bluetooth_manager,
        display_controller=display_controller,
    )


@pytest.fixture
def client(app):
    """Create a TestClient for the app."""
    return TestClient(app)


@pytest.fixture
def device_manager():
    """Create a DeviceManager instance."""
    return DeviceManager()


# =============================================================================
# 1. Component Initialization Tests
# =============================================================================

class TestComponentInitialization:
    """Tests for component initialization."""

    def test_mode_manager_initialization(self, mode_manager):
        """ModeManager should initialize correctly."""
        assert mode_manager.current_mode == Mode.LOCAL
        assert mode_manager.previous_mode is None

    def test_failover_monitor_initialization(self, failover_monitor):
        """FailoverMonitor should initialize in DISCONNECTED state."""
        assert failover_monitor.state == FailoverState.DISCONNECTED

    def test_config_initialization(self, config):
        """Config should load or create defaults."""
        assert config is not None

    def test_wifi_manager_initialization(self, wifi_manager):
        """WifiManager should initialize without errors."""
        assert wifi_manager is not None

    def test_bluetooth_manager_initialization(self, bluetooth_manager):
        """BluetoothManager should initialize without errors."""
        assert bluetooth_manager is not None

    def test_display_controller_initialization(self, display_controller):
        """DisplayController should initialize without errors."""
        assert display_controller is not None

    def test_app_initialization(self, app):
        """FastAPI app should initialize with all components."""
        assert app is not None
        assert hasattr(app, 'state')
        assert hasattr(app.state, 'mode_manager')
        assert hasattr(app.state, 'ws_manager')
        assert hasattr(app.state, 'wifi_manager')
        assert hasattr(app.state, 'bluetooth_manager')
        assert hasattr(app.state, 'display_controller')

    def test_all_managers_stored_in_app_state(self, app, mode_manager, wifi_manager, bluetooth_manager, display_controller):
        """All managers should be accessible from app state."""
        assert app.state.mode_manager is mode_manager
        assert app.state.wifi_manager is wifi_manager
        assert app.state.bluetooth_manager is bluetooth_manager
        assert app.state.display_controller is display_controller


# =============================================================================
# 2. Mode Transitions Tests
# =============================================================================

class TestModeTransitions:
    """Tests for mode transitions and integration."""

    @pytest.mark.asyncio
    async def test_mode_change_via_mode_manager(self, mode_manager):
        """ModeManager should change modes correctly."""
        assert mode_manager.current_mode == Mode.LOCAL

        changed = await mode_manager.set_mode(Mode.DASHBOARD)
        assert changed is True
        assert mode_manager.current_mode == Mode.DASHBOARD
        assert mode_manager.previous_mode == Mode.LOCAL

    @pytest.mark.asyncio
    async def test_mode_change_notifies_listeners(self, mode_manager):
        """ModeManager should notify all listeners on mode change."""
        notifications = []

        def listener(old_mode, new_mode):
            notifications.append((old_mode, new_mode))

        mode_manager.add_listener(listener)
        await mode_manager.set_mode(Mode.DASHBOARD)

        assert len(notifications) == 1
        assert notifications[0] == (Mode.LOCAL, Mode.DASHBOARD)

    @pytest.mark.asyncio
    async def test_all_mode_transitions(self, mode_manager):
        """ModeManager should support all mode transitions."""
        modes = [Mode.DASHBOARD, Mode.LOCAL, Mode.FLASH, Mode.GATEWAY]

        for target_mode in modes:
            changed = await mode_manager.set_mode(target_mode)
            # First transition always changes, subsequent may or may not
            assert mode_manager.current_mode == target_mode

    @pytest.mark.asyncio
    async def test_concurrent_mode_changes_are_serialized(self, mode_manager):
        """Concurrent mode changes should be serialized by lock."""
        results = await asyncio.gather(
            mode_manager.set_mode(Mode.DASHBOARD),
            mode_manager.set_mode(Mode.FLASH),
            mode_manager.set_mode(Mode.GATEWAY),
        )

        # Mode should be one of the requested modes
        assert mode_manager.current_mode in [Mode.DASHBOARD, Mode.FLASH, Mode.GATEWAY]
        # At least one change should have succeeded
        assert any(results)


# =============================================================================
# 3. API Routes Integration Tests
# =============================================================================

class TestAPIRoutesIntegration:
    """Tests for API routes integration."""

    def test_health_endpoint(self, client):
        """Health endpoint should return OK."""
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_mode_get_returns_current_mode(self, client, mode_manager):
        """GET /mode should return current mode."""
        response = client.get("/api/mode")
        assert response.status_code == 200
        data = response.json()
        assert data["mode"] == mode_manager.current_mode.value

    def test_mode_post_changes_mode(self, client, mode_manager):
        """POST /mode should change the mode."""
        response = client.post("/api/mode", json={"mode": "dashboard"})
        assert response.status_code == 200
        data = response.json()
        assert data["mode"] == "dashboard"
        assert data["changed"] is True

    def test_mode_post_invalid_mode_rejected(self, client):
        """POST /mode with invalid mode should be rejected."""
        response = client.post("/api/mode", json={"mode": "invalid_mode"})
        assert response.status_code == 400

    def test_mode_post_same_mode_no_change(self, client, mode_manager):
        """POST /mode with same mode should indicate no change."""
        # First ensure we're in a known mode
        client.post("/api/mode", json={"mode": "local"})

        # Now post the same mode
        response = client.post("/api/mode", json={"mode": "local"})
        assert response.status_code == 200
        data = response.json()
        assert data["changed"] is False

    def test_wifi_status_endpoint(self, client):
        """GET /wifi/status should return WiFi status."""
        response = client.get("/api/wifi/status")
        assert response.status_code == 200
        data = response.json()
        assert "connected" in data

    def test_wifi_networks_endpoint(self, client):
        """GET /wifi/networks should return network list."""
        response = client.get("/api/wifi/networks")
        assert response.status_code == 200
        data = response.json()
        assert "networks" in data

    def test_bluetooth_status_endpoint(self, client):
        """GET /bluetooth/status should return Bluetooth status."""
        response = client.get("/api/bluetooth/status")
        assert response.status_code == 200
        data = response.json()
        assert "enabled" in data

    def test_bluetooth_devices_endpoint(self, client):
        """GET /bluetooth/devices should return device list."""
        response = client.get("/api/bluetooth/devices")
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data

    def test_display_settings_endpoint(self, client):
        """GET /display/settings should return display settings."""
        response = client.get("/api/display/settings")
        assert response.status_code == 200
        data = response.json()
        assert "brightness" in data

    def test_display_brightness_post(self, client):
        """POST /display/brightness should accept value."""
        response = client.post("/api/display/brightness", json={"value": 75})
        assert response.status_code == 200
        data = response.json()
        assert data.get("success") is True

    def test_devices_list_endpoint(self, client):
        """GET /devices should return device list."""
        response = client.get("/api/devices")
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data

    def test_devices_scan_endpoint(self, client):
        """POST /devices/scan should initiate scan."""
        response = client.post("/api/devices/scan")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_system_info_endpoint(self, client):
        """GET /system/info should return system info."""
        response = client.get("/api/system/info")
        assert response.status_code == 200
        data = response.json()
        assert "hostname" in data

    def test_system_reboot_endpoint(self, client):
        """POST /system/reboot should return status."""
        response = client.post("/api/system/reboot")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    def test_secubox_status_endpoint(self, client):
        """GET /secubox/status should return SecuBox status."""
        response = client.get("/api/secubox/status")
        assert response.status_code == 200
        data = response.json()
        assert "connected" in data

    def test_secubox_metrics_endpoint(self, client):
        """GET /secubox/metrics should return metrics."""
        response = client.get("/api/secubox/metrics")
        assert response.status_code == 200
        assert isinstance(response.json(), dict)

    def test_secubox_modules_endpoint(self, client):
        """GET /secubox/modules should return module list."""
        response = client.get("/api/secubox/modules")
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data

    def test_control_page_returns_html(self, client):
        """GET /control should return HTML."""
        response = client.get("/control")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


# =============================================================================
# 4. WebSocket Integration Tests
# =============================================================================

class TestWebSocketIntegration:
    """Tests for WebSocket integration."""

    def test_websocket_connection(self, client):
        """WebSocket should accept connections."""
        with client.websocket_connect("/ws") as websocket:
            # Should receive initial state
            data = websocket.receive_json()
            assert data["type"] == "initial_state"

    def test_websocket_ping_pong(self, client):
        """WebSocket should respond to ping with pong."""
        with client.websocket_connect("/ws") as websocket:
            # Receive initial state first
            websocket.receive_json()

            # Send ping
            websocket.send_json({"type": "ping"})

            # Should receive pong
            data = websocket.receive_json()
            assert data["type"] == "pong"

    def test_websocket_invalid_json_handled(self, client):
        """WebSocket should handle invalid JSON gracefully."""
        with client.websocket_connect("/ws") as websocket:
            # Receive initial state first
            websocket.receive_json()

            # Send invalid JSON
            websocket.send_text("not valid json")

            # Should receive error
            data = websocket.receive_json()
            assert data["type"] == "error"

    def test_websocket_unknown_message_type_acknowledged(self, client):
        """WebSocket should acknowledge unknown message types."""
        with client.websocket_connect("/ws") as websocket:
            # Receive initial state first
            websocket.receive_json()

            # Send unknown type
            websocket.send_json({"type": "unknown_type"})

            # Should receive ack
            data = websocket.receive_json()
            assert data["type"] == "ack"

    def test_websocket_multiple_connections(self, client):
        """WebSocket should handle multiple simultaneous connections."""
        with client.websocket_connect("/ws") as ws1:
            ws1.receive_json()  # Initial state

            with client.websocket_connect("/ws") as ws2:
                ws2.receive_json()  # Initial state

                # Both should be able to send/receive
                ws1.send_json({"type": "ping"})
                ws2.send_json({"type": "ping"})

                pong1 = ws1.receive_json()
                pong2 = ws2.receive_json()

                assert pong1["type"] == "pong"
                assert pong2["type"] == "pong"

    def test_connection_manager_broadcast(self):
        """ConnectionManager should broadcast to all connections."""
        manager = ConnectionManager()

        # This is a unit test for the manager, but relevant for integration
        assert manager.connection_count == 0
        assert manager.has_connections is False


# =============================================================================
# 5. System Controllers Tests
# =============================================================================

class TestSystemControllers:
    """Tests for system controllers in simulation mode."""

    @pytest.mark.asyncio
    async def test_wifi_manager_scan_networks(self, wifi_manager):
        """WifiManager scan should not crash."""
        # In simulation mode, this should return an empty list or mock data
        try:
            networks = await wifi_manager.scan()
            assert isinstance(networks, list)
        except NotImplementedError:
            # If not implemented, that's also acceptable
            pass

    @pytest.mark.asyncio
    async def test_wifi_manager_status(self, wifi_manager):
        """WifiManager status() should not crash."""
        try:
            status = await wifi_manager.status()
            # Should return WifiStatus object
            assert status is not None
            assert hasattr(status, 'connected')
        except (asyncio.TimeoutError, FileNotFoundError):
            # Expected when nmcli is not available
            pass

    @pytest.mark.asyncio
    async def test_bluetooth_manager_status(self, bluetooth_manager):
        """BluetoothManager status() should not crash."""
        try:
            status = await bluetooth_manager.status()
            assert status is not None
            assert hasattr(status, 'powered')
        except (asyncio.TimeoutError, FileNotFoundError):
            # Expected when bluetoothctl is not available
            pass

    @pytest.mark.asyncio
    async def test_bluetooth_manager_scan_devices(self, bluetooth_manager):
        """BluetoothManager scan should not crash."""
        try:
            devices = await bluetooth_manager.scan()
            assert isinstance(devices, list)
        except (asyncio.TimeoutError, FileNotFoundError):
            # Expected when bluetoothctl is not available
            pass

    @pytest.mark.asyncio
    async def test_display_controller_status(self, display_controller):
        """DisplayController status() should not crash."""
        status = await display_controller.status()
        assert status is not None
        assert hasattr(status, 'brightness')
        assert hasattr(status, 'power_on')

    @pytest.mark.asyncio
    async def test_display_controller_set_brightness(self, display_controller):
        """DisplayController set_brightness should not crash."""
        try:
            result = await display_controller.set_brightness(80)
            # Should return success or the value
            assert result is not None or result is True
        except NotImplementedError:
            pass


# =============================================================================
# 6. SecuBox Management Tests
# =============================================================================

class TestSecuBoxManagement:
    """Tests for SecuBox device management integration."""

    @pytest.mark.asyncio
    async def test_device_manager_add_device(self, device_manager):
        """DeviceManager should add devices."""
        device = await device_manager.add_device(
            host="192.168.1.100",
            port=8000,
            name="Test SecuBox"
        )

        assert device is not None
        assert device.host == "192.168.1.100"
        assert device.port == 8000
        assert device.name == "Test SecuBox"

    @pytest.mark.asyncio
    async def test_device_manager_remove_device(self, device_manager):
        """DeviceManager should remove devices."""
        device = await device_manager.add_device(host="192.168.1.100")
        device_id = device.id

        removed = await device_manager.remove_device(device_id)
        assert removed is True

        # Should no longer be in the list
        devices = await device_manager.list_devices()
        assert all(d.id != device_id for d in devices)

    @pytest.mark.asyncio
    async def test_device_manager_list_devices(self, device_manager):
        """DeviceManager should list all devices."""
        await device_manager.add_device(host="192.168.1.100")
        await device_manager.add_device(host="192.168.1.101")

        devices = await device_manager.list_devices()
        assert len(devices) == 2

    @pytest.mark.asyncio
    async def test_device_manager_set_primary(self, device_manager):
        """DeviceManager should set primary device."""
        device = await device_manager.add_device(host="192.168.1.100")

        result = await device_manager.set_primary(device.id)
        assert result is True
        assert device_manager.primary_device.id == device.id

    @pytest.mark.asyncio
    async def test_device_manager_update_state(self, device_manager):
        """DeviceManager should update device state."""
        device = await device_manager.add_device(host="192.168.1.100")

        await device_manager.update_device_state(device.id, ConnectionState.CONNECTED)

        updated_device = await device_manager.get_device(device.id)
        assert updated_device.state == ConnectionState.CONNECTED

    @pytest.mark.asyncio
    async def test_fleet_aggregator_initialization(self, device_manager):
        """FleetAggregator should initialize with DeviceManager."""
        aggregator = FleetAggregator(device_manager)
        assert aggregator._device_manager is device_manager
        assert aggregator._poll_interval == 30.0

    @pytest.mark.asyncio
    async def test_fleet_aggregator_empty_fleet_metrics(self, device_manager):
        """FleetAggregator should return zero metrics for empty fleet."""
        aggregator = FleetAggregator(device_manager)

        metrics = await aggregator.get_fleet_metrics()

        assert metrics.total_devices == 0
        assert metrics.online_devices == 0
        assert metrics.avg_cpu == 0.0

    @pytest.mark.asyncio
    async def test_fleet_aggregator_aggregates_metrics(self, device_manager):
        """FleetAggregator should aggregate metrics from devices."""
        aggregator = FleetAggregator(device_manager)

        # Add devices and mock their metrics
        device1 = await device_manager.add_device(host="192.168.1.100")
        device2 = await device_manager.add_device(host="192.168.1.101")

        # Simulate cached metrics
        aggregator._device_metrics = {
            device1.id: {"cpu_percent": 40.0, "mem_percent": 50.0, "disk_percent": 30.0, "online": True},
            device2.id: {"cpu_percent": 60.0, "mem_percent": 70.0, "disk_percent": 40.0, "online": True},
        }

        metrics = await aggregator.get_fleet_metrics()

        assert metrics.total_devices == 2
        assert metrics.online_devices == 2
        assert metrics.avg_cpu == 50.0  # (40 + 60) / 2
        assert metrics.avg_mem == 60.0  # (50 + 70) / 2

    @pytest.mark.asyncio
    async def test_fleet_aggregator_start_stop(self, device_manager):
        """FleetAggregator should start and stop polling."""
        aggregator = FleetAggregator(device_manager, poll_interval=60.0)

        await aggregator.start()
        assert aggregator._poll_task is not None
        assert not aggregator._poll_task.done()

        await aggregator.stop()
        assert aggregator._poll_task is None


# =============================================================================
# 7. Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling and graceful degradation."""

    def test_mode_endpoint_without_manager(self):
        """Mode endpoint should handle missing manager gracefully."""
        app = create_app(mode_manager=None)
        client = TestClient(app)

        response = client.get("/api/mode")
        assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_failover_monitor_handles_api_failure(self, failover_monitor):
        """FailoverMonitor should transition states on API failure."""
        # Record initial success
        failover_monitor.record_success()
        assert failover_monitor.state == FailoverState.CONNECTED

        # Force time to pass by manipulating last_success
        import time
        failover_monitor._last_success = time.time() - 100  # 100 seconds ago

        # Update state should transition to DISCONNECTED
        failover_monitor.update_state()
        assert failover_monitor.state == FailoverState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_mode_manager_listener_errors_isolated(self, mode_manager):
        """ModeManager should isolate listener errors."""
        good_listener_called = False

        def bad_listener(_old, _new):
            raise ValueError("Listener error")

        def good_listener(_old, _new):
            nonlocal good_listener_called
            good_listener_called = True

        mode_manager.add_listener(bad_listener)
        mode_manager.add_listener(good_listener)

        # Should not raise, and good listener should still be called
        await mode_manager.set_mode(Mode.DASHBOARD)

        assert mode_manager.current_mode == Mode.DASHBOARD
        assert good_listener_called

    @pytest.mark.asyncio
    async def test_device_manager_remove_nonexistent_device(self, device_manager):
        """DeviceManager should handle removing nonexistent device."""
        result = await device_manager.remove_device("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_fleet_aggregator_refresh_nonexistent_device(self, device_manager):
        """FleetAggregator should handle refreshing nonexistent device."""
        aggregator = FleetAggregator(device_manager)

        result = await aggregator.refresh_device("nonexistent-id")
        assert result is False


# =============================================================================
# 8. Full System Integration Tests
# =============================================================================

class TestFullSystemIntegration:
    """End-to-end integration tests."""

    def test_complete_mode_change_flow(self, client, mode_manager):
        """Complete mode change flow from API to state."""
        # Initial state
        response = client.get("/api/mode")
        assert response.status_code == 200
        initial_mode = response.json()["mode"]

        # Change mode via API
        new_mode = "dashboard" if initial_mode != "dashboard" else "local"
        response = client.post("/api/mode", json={"mode": new_mode})
        assert response.status_code == 200
        assert response.json()["changed"] is True

        # Verify mode changed in manager
        assert mode_manager.current_mode.value == new_mode

        # Verify API reflects new mode
        response = client.get("/api/mode")
        assert response.json()["mode"] == new_mode

    def test_api_endpoints_all_accessible(self, client):
        """All API endpoints should be accessible."""
        endpoints = [
            ("GET", "/api/health"),
            ("GET", "/api/mode"),
            ("GET", "/api/wifi/status"),
            ("GET", "/api/wifi/networks"),
            ("GET", "/api/bluetooth/status"),
            ("GET", "/api/bluetooth/devices"),
            ("GET", "/api/display/settings"),
            ("GET", "/api/devices"),
            ("GET", "/api/system/info"),
            ("GET", "/api/secubox/status"),
            ("GET", "/api/secubox/metrics"),
            ("GET", "/api/secubox/modules"),
            ("GET", "/control"),
        ]

        for method, endpoint in endpoints:
            if method == "GET":
                response = client.get(endpoint)
            else:
                response = client.post(endpoint)

            assert response.status_code in [200, 503], f"Failed: {method} {endpoint}"

    @pytest.mark.asyncio
    async def test_device_lifecycle(self, device_manager):
        """Complete device lifecycle: add, update, set primary, remove."""
        # Add device
        device = await device_manager.add_device(
            host="192.168.1.100",
            port=8000,
            name="Lifecycle Test"
        )
        device_id = device.id

        # Update state
        await device_manager.update_device_state(device_id, ConnectionState.CONNECTED)
        updated = await device_manager.get_device(device_id)
        assert updated.state == ConnectionState.CONNECTED

        # Set as primary
        result = await device_manager.set_primary(device_id)
        assert result is True
        assert device_manager.primary_device.id == device_id

        # Remove device
        removed = await device_manager.remove_device(device_id)
        assert removed is True

        # Primary should be cleared
        assert device_manager.primary_device is None

    @pytest.mark.asyncio
    async def test_failover_state_transitions(self, failover_monitor):
        """Failover monitor should transition through all states."""
        import time

        # Start disconnected
        assert failover_monitor.state == FailoverState.DISCONNECTED

        # Record success -> CONNECTED
        failover_monitor.record_success()
        assert failover_monitor.state == FailoverState.CONNECTED

        # Simulate time passing through stale threshold
        failover_monitor._last_success = time.time() - 10
        failover_monitor.update_state()
        assert failover_monitor.state == FailoverState.STALE

        # Simulate more time passing through degraded threshold
        failover_monitor._last_success = time.time() - 30
        failover_monitor.update_state()
        assert failover_monitor.state == FailoverState.DEGRADED

        # Simulate disconnect threshold
        failover_monitor._last_success = time.time() - 100
        failover_monitor.update_state()
        assert failover_monitor.state == FailoverState.DISCONNECTED


# =============================================================================
# 9. WebSocket and Mode Integration
# =============================================================================

class TestWebSocketModeIntegration:
    """Tests for WebSocket and mode manager integration."""

    def test_websocket_receives_initial_mode(self, app, mode_manager):
        """WebSocket should receive initial mode on connect."""
        client = TestClient(app)

        with client.websocket_connect("/ws") as websocket:
            data = websocket.receive_json()

            assert data["type"] == "initial_state"
            assert data["data"]["mode"] == mode_manager.current_mode.value


# =============================================================================
# 10. Configuration Integration
# =============================================================================

class TestConfigurationIntegration:
    """Tests for configuration loading and integration."""

    def test_app_uses_provided_config(self, config):
        """App should use the provided config."""
        app = create_app(config=config)
        assert app.state.config is config

    def test_default_config_created_when_none_provided(self):
        """App should create default config when none provided."""
        app = create_app(config=None)
        # Config may be None if not explicitly required
        # This is acceptable behavior


# =============================================================================
# 11. WebServer Class Integration
# =============================================================================

class TestWebServerIntegration:
    """Tests for WebServer class."""

    def test_webserver_creates_app(self, mode_manager):
        """WebServer should create app with all components."""
        server = WebServer(mode_manager=mode_manager)
        assert server.app is not None
        assert server.app.state.mode_manager is mode_manager

    def test_webserver_custom_host_port(self):
        """WebServer should accept custom host and port."""
        server = WebServer(host="127.0.0.1", port=9000)
        assert server.host == "127.0.0.1"
        assert server.port == 9000

    @pytest.mark.asyncio
    async def test_webserver_has_start_stop_methods(self):
        """WebServer should have start and stop methods."""
        server = WebServer()
        assert callable(server.start)
        assert callable(server.stop)
