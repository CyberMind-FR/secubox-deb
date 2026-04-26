"""
SecuBox Eye Remote — Tests for SecuBox Device Manager
Test suite for fleet management functionality.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from agent.secubox.device_manager import (
    DeviceManager,
    SecuBoxDevice,
    ConnectionState,
)


class TestSecuBoxDevice:
    """Tests for SecuBoxDevice dataclass."""

    def test_device_creation_defaults(self):
        """Device should have sensible defaults."""
        device = SecuBoxDevice(
            id="test-001",
            name="Test SecuBox",
            host="192.168.1.100"
        )
        assert device.id == "test-001"
        assert device.name == "Test SecuBox"
        assert device.host == "192.168.1.100"
        assert device.port == 8000
        assert device.transport == "http"
        assert device.active is True
        assert device.state == ConnectionState.UNKNOWN
        assert device.last_seen is None
        assert device.metrics == {}

    def test_device_custom_values(self):
        """Device should accept custom values."""
        device = SecuBoxDevice(
            id="custom-001",
            name="Custom Box",
            host="10.55.0.1",
            port=9000,
            transport="otg",
            active=False,
            state=ConnectionState.CONNECTED,
            last_seen=1234567890.0,
            metrics={"cpu_percent": 25.0}
        )
        assert device.port == 9000
        assert device.transport == "otg"
        assert device.active is False
        assert device.state == ConnectionState.CONNECTED
        assert device.last_seen == 1234567890.0
        assert device.metrics["cpu_percent"] == 25.0


class TestConnectionState:
    """Tests for ConnectionState enum."""

    def test_connection_states_exist(self):
        """All connection states should be defined."""
        assert ConnectionState.UNKNOWN.value == "unknown"
        assert ConnectionState.CONNECTED.value == "connected"
        assert ConnectionState.DISCONNECTED.value == "disconnected"
        assert ConnectionState.ERROR.value == "error"


class TestDeviceManagerInit:
    """Tests for DeviceManager initialization."""

    def test_device_manager_init_empty(self):
        """Manager should initialize with empty state."""
        manager = DeviceManager()
        assert manager._devices == {}
        assert manager._primary_id is None
        assert manager._config is None

    def test_device_manager_init_with_config(self):
        """Manager should accept config on initialization."""
        config = MagicMock()
        manager = DeviceManager(config=config)
        assert manager._config == config


@pytest.mark.asyncio
class TestAddDevice:
    """Tests for adding devices to the fleet."""

    async def test_add_device_basic(self):
        """Should add a device with basic parameters."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")

        assert device is not None
        assert device.host == "192.168.1.100"
        assert device.port == 8000
        assert device.id is not None
        assert len(device.id) > 0

    async def test_add_device_with_port(self):
        """Should add a device with custom port."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100", port=9000)

        assert device.port == 9000

    async def test_add_device_with_name(self):
        """Should add a device with custom name."""
        manager = DeviceManager()
        device = await manager.add_device(
            host="192.168.1.100",
            name="Main SecuBox"
        )

        assert device.name == "Main SecuBox"

    async def test_add_device_generates_default_name(self):
        """Should generate default name from host if not provided."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")

        assert device.name is not None
        assert "192.168.1.100" in device.name

    async def test_add_device_generates_unique_id(self):
        """Should generate unique ID for each device."""
        manager = DeviceManager()
        device1 = await manager.add_device(host="192.168.1.100")
        device2 = await manager.add_device(host="192.168.1.101")

        assert device1.id != device2.id

    async def test_add_device_stores_in_devices(self):
        """Added device should be stored in internal dict."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")

        assert device.id in manager._devices
        assert manager._devices[device.id] == device


@pytest.mark.asyncio
class TestRemoveDevice:
    """Tests for removing devices from the fleet."""

    async def test_remove_device_existing(self):
        """Should remove an existing device."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")
        device_id = device.id

        result = await manager.remove_device(device_id)

        assert result is True
        assert device_id not in manager._devices

    async def test_remove_device_nonexistent(self):
        """Should return False for non-existent device."""
        manager = DeviceManager()

        result = await manager.remove_device("nonexistent-id")

        assert result is False

    async def test_remove_primary_clears_primary(self):
        """Removing primary device should clear primary_id."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")
        await manager.set_primary(device.id)

        assert manager._primary_id == device.id

        await manager.remove_device(device.id)

        assert manager._primary_id is None


@pytest.mark.asyncio
class TestListDevices:
    """Tests for listing devices in the fleet."""

    async def test_list_devices_empty(self):
        """Should return empty list when no devices."""
        manager = DeviceManager()
        devices = await manager.list_devices()

        assert devices == []

    async def test_list_devices_single(self):
        """Should return list with one device."""
        manager = DeviceManager()
        await manager.add_device(host="192.168.1.100")

        devices = await manager.list_devices()

        assert len(devices) == 1
        assert devices[0].host == "192.168.1.100"

    async def test_list_devices_multiple(self):
        """Should return list with all devices."""
        manager = DeviceManager()
        await manager.add_device(host="192.168.1.100")
        await manager.add_device(host="192.168.1.101")
        await manager.add_device(host="192.168.1.102")

        devices = await manager.list_devices()

        assert len(devices) == 3
        hosts = [d.host for d in devices]
        assert "192.168.1.100" in hosts
        assert "192.168.1.101" in hosts
        assert "192.168.1.102" in hosts


@pytest.mark.asyncio
class TestSetPrimary:
    """Tests for setting the primary device."""

    async def test_set_primary_valid(self):
        """Should set primary device successfully."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")

        result = await manager.set_primary(device.id)

        assert result is True
        assert manager._primary_id == device.id

    async def test_set_primary_invalid(self):
        """Should return False for non-existent device."""
        manager = DeviceManager()

        result = await manager.set_primary("nonexistent-id")

        assert result is False
        assert manager._primary_id is None

    async def test_primary_device_property(self):
        """Should return primary device via property."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")
        await manager.set_primary(device.id)

        primary = manager.primary_device

        assert primary is not None
        assert primary.id == device.id

    async def test_primary_device_property_none(self):
        """Should return None when no primary set."""
        manager = DeviceManager()

        primary = manager.primary_device

        assert primary is None


@pytest.mark.asyncio
class TestGetDevice:
    """Tests for getting a specific device."""

    async def test_get_device_existing(self):
        """Should return device by ID."""
        manager = DeviceManager()
        original = await manager.add_device(host="192.168.1.100", name="Test")

        device = await manager.get_device(original.id)

        assert device is not None
        assert device.id == original.id
        assert device.name == "Test"

    async def test_get_device_nonexistent(self):
        """Should return None for non-existent ID."""
        manager = DeviceManager()

        device = await manager.get_device("nonexistent-id")

        assert device is None


@pytest.mark.asyncio
class TestUpdateDeviceState:
    """Tests for updating device connection state."""

    async def test_update_state_connected(self):
        """Should update device to connected state."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")

        await manager.update_device_state(device.id, ConnectionState.CONNECTED)

        updated = await manager.get_device(device.id)
        assert updated.state == ConnectionState.CONNECTED

    async def test_update_state_disconnected(self):
        """Should update device to disconnected state."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")

        await manager.update_device_state(device.id, ConnectionState.DISCONNECTED)

        updated = await manager.get_device(device.id)
        assert updated.state == ConnectionState.DISCONNECTED

    async def test_update_state_sets_last_seen(self):
        """Should update last_seen timestamp when state changes."""
        manager = DeviceManager()
        device = await manager.add_device(host="192.168.1.100")

        assert device.last_seen is None

        before = time.time()
        await manager.update_device_state(device.id, ConnectionState.CONNECTED)
        after = time.time()

        updated = await manager.get_device(device.id)
        assert updated.last_seen is not None
        assert before <= updated.last_seen <= after

    async def test_update_state_nonexistent_device(self):
        """Should handle non-existent device gracefully."""
        manager = DeviceManager()

        # Should not raise
        await manager.update_device_state("nonexistent", ConnectionState.ERROR)


@pytest.mark.asyncio
class TestDuplicateDeviceHandling:
    """Tests for handling duplicate devices."""

    async def test_duplicate_host_creates_separate_devices(self):
        """Adding same host twice should create two devices."""
        manager = DeviceManager()
        device1 = await manager.add_device(host="192.168.1.100")
        device2 = await manager.add_device(host="192.168.1.100")

        # Two separate device objects
        assert device1.id != device2.id
        assert len(manager._devices) == 2

    async def test_duplicate_host_different_ports(self):
        """Same host with different ports should be different devices."""
        manager = DeviceManager()
        device1 = await manager.add_device(host="192.168.1.100", port=8000)
        device2 = await manager.add_device(host="192.168.1.100", port=9000)

        assert device1.id != device2.id


@pytest.mark.asyncio
class TestScanNetwork:
    """Tests for network scanning functionality."""

    async def test_scan_network_returns_list(self):
        """Scan should return a list of devices."""
        manager = DeviceManager()

        # Stub implementation returns empty list
        devices = await manager.scan_network()

        assert isinstance(devices, list)

    async def test_scan_network_custom_range(self):
        """Scan should accept custom network range."""
        manager = DeviceManager()

        # Should not raise with custom network
        devices = await manager.scan_network(network="10.0.0.0/24")

        assert isinstance(devices, list)


@pytest.mark.asyncio
class TestLoadFromConfig:
    """Tests for loading devices from configuration."""

    async def test_load_from_config_no_config(self):
        """Should handle missing config gracefully."""
        manager = DeviceManager()

        # Should not raise
        await manager.load_from_config()

        # No devices loaded
        devices = await manager.list_devices()
        assert devices == []

    async def test_load_from_config_with_devices(self):
        """Should load devices from config."""
        mock_config = MagicMock()
        mock_config.secuboxes = MagicMock()
        mock_config.secuboxes.devices = [
            MagicMock(
                id="box-001",
                name="Primary",
                host="192.168.1.100",
                port=8000,
                active=True
            ),
            MagicMock(
                id="box-002",
                name="Secondary",
                host="192.168.1.101",
                port=8000,
                active=False
            ),
        ]
        mock_config.secuboxes.primary = "Primary"

        manager = DeviceManager(config=mock_config)
        await manager.load_from_config()

        devices = await manager.list_devices()
        assert len(devices) == 2


@pytest.mark.asyncio
class TestThreadSafety:
    """Tests for thread-safety with asyncio.Lock."""

    async def test_concurrent_add_devices(self):
        """Concurrent adds should be thread-safe."""
        manager = DeviceManager()

        async def add_device(i):
            return await manager.add_device(host=f"192.168.1.{i}")

        # Add 10 devices concurrently
        tasks = [add_device(i) for i in range(10)]
        devices = await asyncio.gather(*tasks)

        # All devices should be added
        assert len(devices) == 10
        assert len(manager._devices) == 10

        # All IDs should be unique
        ids = [d.id for d in devices]
        assert len(set(ids)) == 10

    async def test_concurrent_operations(self):
        """Mixed concurrent operations should be safe."""
        manager = DeviceManager()

        # Pre-add some devices
        device1 = await manager.add_device(host="192.168.1.100")
        device2 = await manager.add_device(host="192.168.1.101")

        async def operations():
            await manager.list_devices()
            await manager.get_device(device1.id)
            await manager.update_device_state(device2.id, ConnectionState.CONNECTED)
            await manager.add_device(host="192.168.1.200")
            await manager.list_devices()

        # Run multiple operations concurrently
        tasks = [operations() for _ in range(5)]
        await asyncio.gather(*tasks)

        # Manager should still be consistent
        devices = await manager.list_devices()
        assert len(devices) >= 2  # Original two plus any added
