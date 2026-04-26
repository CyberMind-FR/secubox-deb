"""
SecuBox Eye Remote — Tests for Fleet Aggregator
Test suite for fleet aggregation functionality in Gateway mode.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from agent.secubox.fleet import (
    FleetAggregator,
    FleetMetrics,
    DeviceStatus,
)
from agent.secubox.device_manager import (
    DeviceManager,
    SecuBoxDevice,
    ConnectionState,
)
from agent.secubox.remote_control import (
    SecuBoxClient,
    SecuBoxMetrics,
    SecuBoxAlert,
)


class TestFleetMetrics:
    """Tests for FleetMetrics dataclass."""

    def test_fleet_metrics_creation(self):
        """FleetMetrics should initialize with all fields."""
        metrics = FleetMetrics(
            total_devices=5,
            online_devices=4,
            offline_devices=1,
            avg_cpu=45.5,
            avg_mem=60.2,
            avg_disk=30.0,
            max_cpu=78.5,
            max_mem=85.0,
            total_alerts=12,
            critical_alerts=2,
        )
        assert metrics.total_devices == 5
        assert metrics.online_devices == 4
        assert metrics.offline_devices == 1
        assert metrics.avg_cpu == 45.5
        assert metrics.avg_mem == 60.2
        assert metrics.avg_disk == 30.0
        assert metrics.max_cpu == 78.5
        assert metrics.max_mem == 85.0
        assert metrics.total_alerts == 12
        assert metrics.critical_alerts == 2


class TestDeviceStatus:
    """Tests for DeviceStatus dataclass."""

    def test_device_status_creation(self):
        """DeviceStatus should initialize with all fields."""
        status = DeviceStatus(
            device_id="dev-001",
            name="Primary SecuBox",
            online=True,
            cpu=55.5,
            mem=72.0,
            alert_count=3,
            last_update=1700000000.0,
        )
        assert status.device_id == "dev-001"
        assert status.name == "Primary SecuBox"
        assert status.online is True
        assert status.cpu == 55.5
        assert status.mem == 72.0
        assert status.alert_count == 3
        assert status.last_update == 1700000000.0

    def test_device_status_optional_fields(self):
        """DeviceStatus should allow None for optional fields."""
        status = DeviceStatus(
            device_id="dev-002",
            name="Offline SecuBox",
            online=False,
            cpu=None,
            mem=None,
            alert_count=0,
            last_update=None,
        )
        assert status.cpu is None
        assert status.mem is None
        assert status.last_update is None


class TestFleetAggregatorInit:
    """Tests for FleetAggregator initialization."""

    def test_fleet_aggregator_init(self):
        """FleetAggregator should initialize with device manager."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        assert aggregator._device_manager is manager
        assert aggregator._poll_interval == 30.0
        assert aggregator._clients == {}
        assert aggregator._device_metrics == {}
        assert aggregator._device_alerts == {}
        assert aggregator._poll_task is None

    def test_fleet_aggregator_custom_interval(self):
        """FleetAggregator should accept custom poll interval."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager, poll_interval=15.0)

        assert aggregator._poll_interval == 15.0


@pytest.mark.asyncio
class TestStartStopPolling:
    """Tests for start/stop polling lifecycle."""

    async def test_start_creates_poll_task(self):
        """Start should create background polling task."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager, poll_interval=60.0)

        await aggregator.start()

        assert aggregator._poll_task is not None
        assert not aggregator._poll_task.done()

        await aggregator.stop()

    async def test_stop_cancels_poll_task(self):
        """Stop should cancel the polling task."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager, poll_interval=60.0)

        await aggregator.start()
        poll_task = aggregator._poll_task

        await aggregator.stop()

        assert aggregator._poll_task is None
        assert poll_task.cancelled() or poll_task.done()

    async def test_stop_idempotent(self):
        """Stop should be safe to call multiple times."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        # Should not raise when already stopped
        await aggregator.stop()
        await aggregator.stop()

    async def test_stop_closes_clients(self):
        """Stop should close all client connections."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager, poll_interval=60.0)

        # Add a mock client
        mock_client = AsyncMock(spec=SecuBoxClient)
        aggregator._clients["dev-001"] = mock_client

        await aggregator.start()
        await aggregator.stop()

        mock_client.close.assert_called_once()
        assert aggregator._clients == {}


@pytest.mark.asyncio
class TestGetFleetMetricsEmpty:
    """Tests for fleet metrics with no devices."""

    async def test_get_fleet_metrics_empty(self):
        """Should return zero metrics when no devices."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        metrics = await aggregator.get_fleet_metrics()

        assert metrics.total_devices == 0
        assert metrics.online_devices == 0
        assert metrics.offline_devices == 0
        assert metrics.avg_cpu == 0.0
        assert metrics.avg_mem == 0.0
        assert metrics.avg_disk == 0.0
        assert metrics.max_cpu == 0.0
        assert metrics.max_mem == 0.0
        assert metrics.total_alerts == 0
        assert metrics.critical_alerts == 0


@pytest.mark.asyncio
class TestGetFleetMetricsWithDevices:
    """Tests for fleet metrics aggregation."""

    async def test_get_fleet_metrics_with_devices(self):
        """Should aggregate metrics from multiple devices."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        # Add devices to manager first to get actual IDs
        device1 = await manager.add_device(host="192.168.1.100")
        device2 = await manager.add_device(host="192.168.1.101")

        # Simulate cached metrics using actual device IDs
        aggregator._device_metrics = {
            device1.id: {
                "cpu_percent": 40.0,
                "mem_percent": 50.0,
                "disk_percent": 30.0,
                "online": True,
            },
            device2.id: {
                "cpu_percent": 60.0,
                "mem_percent": 70.0,
                "disk_percent": 40.0,
                "online": True,
            },
        }
        aggregator._device_alerts = {
            device1.id: [
                {"level": "info"},
                {"level": "warn"},
            ],
            device2.id: [
                {"level": "critical"},
            ],
        }

        metrics = await aggregator.get_fleet_metrics()

        assert metrics.total_devices == 2
        assert metrics.online_devices == 2
        assert metrics.offline_devices == 0
        assert metrics.avg_cpu == 50.0  # (40 + 60) / 2
        assert metrics.avg_mem == 60.0  # (50 + 70) / 2
        assert metrics.avg_disk == 35.0  # (30 + 40) / 2
        assert metrics.max_cpu == 60.0
        assert metrics.max_mem == 70.0
        assert metrics.total_alerts == 3
        assert metrics.critical_alerts == 1

    async def test_get_fleet_metrics_with_offline_device(self):
        """Should count offline devices correctly."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        aggregator._device_metrics = {
            "dev-001": {
                "cpu_percent": 50.0,
                "mem_percent": 60.0,
                "disk_percent": 40.0,
                "online": True,
            },
            "dev-002": {
                "online": False,
            },
        }

        device1 = await manager.add_device(host="192.168.1.100")
        device2 = await manager.add_device(host="192.168.1.101")

        # Update device IDs in metrics to match
        aggregator._device_metrics = {
            device1.id: {
                "cpu_percent": 50.0,
                "mem_percent": 60.0,
                "disk_percent": 40.0,
                "online": True,
            },
            device2.id: {
                "online": False,
            },
        }

        metrics = await aggregator.get_fleet_metrics()

        assert metrics.total_devices == 2
        assert metrics.online_devices == 1
        assert metrics.offline_devices == 1
        # Averages should only include online devices
        assert metrics.avg_cpu == 50.0
        assert metrics.avg_mem == 60.0


@pytest.mark.asyncio
class TestGetFleetStatus:
    """Tests for fleet device status listing."""

    async def test_get_fleet_status_empty(self):
        """Should return empty list when no devices."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        status_list = await aggregator.get_fleet_status()

        assert status_list == []

    async def test_get_fleet_status_with_devices(self):
        """Should return status for all devices."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device1 = await manager.add_device(host="192.168.1.100", name="Box-A")
        device2 = await manager.add_device(host="192.168.1.101", name="Box-B")

        aggregator._device_metrics = {
            device1.id: {
                "cpu_percent": 45.0,
                "mem_percent": 55.0,
                "online": True,
                "last_update": 1700000000.0,
            },
            device2.id: {
                "cpu_percent": 65.0,
                "mem_percent": 75.0,
                "online": True,
                "last_update": 1700000001.0,
            },
        }
        aggregator._device_alerts = {
            device1.id: [{"level": "info"}],
            device2.id: [],
        }

        status_list = await aggregator.get_fleet_status()

        assert len(status_list) == 2

        # Find status by device ID
        status_map = {s.device_id: s for s in status_list}

        assert status_map[device1.id].name == "Box-A"
        assert status_map[device1.id].online is True
        assert status_map[device1.id].cpu == 45.0
        assert status_map[device1.id].mem == 55.0
        assert status_map[device1.id].alert_count == 1

        assert status_map[device2.id].name == "Box-B"
        assert status_map[device2.id].alert_count == 0


@pytest.mark.asyncio
class TestGetAllAlerts:
    """Tests for aggregated alerts retrieval."""

    async def test_get_all_alerts_empty(self):
        """Should return empty list when no alerts."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        alerts = await aggregator.get_all_alerts()

        assert alerts == []

    async def test_get_all_alerts_sorted_by_timestamp(self):
        """Should return alerts sorted by timestamp descending."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        aggregator._device_alerts = {
            "dev-001": [
                {"id": "a1", "timestamp": 1000.0, "level": "info"},
                {"id": "a3", "timestamp": 3000.0, "level": "warn"},
            ],
            "dev-002": [
                {"id": "a2", "timestamp": 2000.0, "level": "critical"},
                {"id": "a4", "timestamp": 4000.0, "level": "info"},
            ],
        }

        alerts = await aggregator.get_all_alerts()

        assert len(alerts) == 4
        # Should be sorted newest first
        assert alerts[0]["id"] == "a4"
        assert alerts[1]["id"] == "a3"
        assert alerts[2]["id"] == "a2"
        assert alerts[3]["id"] == "a1"

    async def test_get_all_alerts_with_limit(self):
        """Should respect limit parameter."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        aggregator._device_alerts = {
            "dev-001": [
                {"id": f"a{i}", "timestamp": float(i * 1000), "level": "info"}
                for i in range(100)
            ],
        }

        alerts = await aggregator.get_all_alerts(limit=10)

        assert len(alerts) == 10

    async def test_get_all_alerts_includes_device_id(self):
        """Alerts should include source device ID."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        aggregator._device_alerts = {
            "dev-001": [
                {"id": "a1", "timestamp": 1000.0, "level": "info"},
            ],
        }

        alerts = await aggregator.get_all_alerts()

        assert len(alerts) == 1
        assert alerts[0]["device_id"] == "dev-001"


@pytest.mark.asyncio
class TestDeviceGoesOffline:
    """Tests for handling device disconnection."""

    async def test_device_goes_offline_updates_state(self):
        """Should update device state when polling fails."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager, poll_interval=60.0)

        device = await manager.add_device(host="192.168.1.100")
        await manager.update_device_state(device.id, ConnectionState.CONNECTED)

        # Create mock client that fails
        mock_client = AsyncMock(spec=SecuBoxClient)
        mock_client.health_check.return_value = False
        aggregator._clients[device.id] = mock_client

        # Poll the device
        await aggregator._poll_device(device)

        # Device metrics should show offline
        assert device.id in aggregator._device_metrics
        assert aggregator._device_metrics[device.id]["online"] is False

    async def test_offline_device_clears_metrics(self):
        """Offline device should clear stale metrics."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device = await manager.add_device(host="192.168.1.100")

        # Set existing metrics
        aggregator._device_metrics[device.id] = {
            "cpu_percent": 50.0,
            "mem_percent": 60.0,
            "online": True,
        }

        # Create mock client that fails
        mock_client = AsyncMock(spec=SecuBoxClient)
        mock_client.health_check.return_value = False
        aggregator._clients[device.id] = mock_client

        # Poll the device
        await aggregator._poll_device(device)

        # Metrics should only contain online status
        assert aggregator._device_metrics[device.id]["online"] is False
        assert "cpu_percent" not in aggregator._device_metrics[device.id]


@pytest.mark.asyncio
class TestRefreshDevice:
    """Tests for manual device refresh."""

    async def test_refresh_device_success(self):
        """Should refresh device metrics on demand."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device = await manager.add_device(host="192.168.1.100")

        # Mock the internal poll method
        with patch.object(aggregator, '_poll_device', new_callable=AsyncMock) as mock_poll:
            result = await aggregator.refresh_device(device.id)

        assert result is True
        mock_poll.assert_called_once()

    async def test_refresh_device_not_found(self):
        """Should return False for unknown device."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        result = await aggregator.refresh_device("nonexistent-id")

        assert result is False

    async def test_refresh_device_creates_client(self):
        """Should create client if not exists."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device = await manager.add_device(host="192.168.1.100")

        # Mock the client creation and poll
        with patch.object(aggregator, '_ensure_client', new_callable=AsyncMock) as mock_ensure:
            with patch.object(aggregator, '_poll_device', new_callable=AsyncMock):
                await aggregator.refresh_device(device.id)

        mock_ensure.assert_called_once_with(device)


@pytest.mark.asyncio
class TestPollDevices:
    """Tests for background polling."""

    async def test_poll_devices_polls_all_active(self):
        """Should poll all active devices."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device1 = await manager.add_device(host="192.168.1.100")
        device2 = await manager.add_device(host="192.168.1.101")

        poll_calls = []

        async def track_poll(device):
            poll_calls.append(device.id)

        with patch.object(aggregator, '_poll_device', side_effect=track_poll):
            # Simulate one poll cycle
            devices = await manager.list_devices()
            for device in devices:
                await aggregator._poll_device(device)

        assert device1.id in poll_calls
        assert device2.id in poll_calls

    async def test_poll_device_with_working_client(self):
        """Should update metrics from successful poll."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device = await manager.add_device(host="192.168.1.100")

        # Create mock client with metrics
        mock_client = AsyncMock(spec=SecuBoxClient)
        mock_client.health_check.return_value = True
        mock_client.get_metrics.return_value = SecuBoxMetrics(
            cpu_percent=45.5,
            mem_percent=60.0,
            disk_percent=35.0,
            load_avg=1.2,
            temp=42.0,
            wifi_rssi=-55,
            uptime_seconds=86400,
        )
        mock_client.get_alerts.return_value = [
            SecuBoxAlert(
                id="alert-1",
                level="warn",
                module="AUTH",
                message="Test alert",
                timestamp=1700000000.0,
            )
        ]

        aggregator._clients[device.id] = mock_client

        await aggregator._poll_device(device)

        # Verify metrics were stored
        assert device.id in aggregator._device_metrics
        metrics = aggregator._device_metrics[device.id]
        assert metrics["cpu_percent"] == 45.5
        assert metrics["mem_percent"] == 60.0
        assert metrics["disk_percent"] == 35.0
        assert metrics["online"] is True

        # Verify alerts were stored
        assert device.id in aggregator._device_alerts
        assert len(aggregator._device_alerts[device.id]) == 1


@pytest.mark.asyncio
class TestEnsureClient:
    """Tests for client lifecycle management."""

    async def test_ensure_client_creates_new(self):
        """Should create new client for new device."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device = SecuBoxDevice(
            id="dev-001",
            name="Test",
            host="192.168.1.100",
            port=8000,
        )

        client = await aggregator._ensure_client(device)

        assert client is not None
        assert "dev-001" in aggregator._clients
        assert aggregator._clients["dev-001"] is client

        # Cleanup
        await client.close()

    async def test_ensure_client_reuses_existing(self):
        """Should reuse existing client."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device = SecuBoxDevice(
            id="dev-001",
            name="Test",
            host="192.168.1.100",
            port=8000,
        )

        client1 = await aggregator._ensure_client(device)
        client2 = await aggregator._ensure_client(device)

        assert client1 is client2

        # Cleanup
        await client1.close()


@pytest.mark.asyncio
class TestConcurrencyAndLocking:
    """Tests for thread-safety with asyncio.Lock."""

    async def test_concurrent_metrics_access(self):
        """Concurrent metric reads should be safe."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device = await manager.add_device(host="192.168.1.100")
        aggregator._device_metrics[device.id] = {
            "cpu_percent": 50.0,
            "mem_percent": 60.0,
            "online": True,
        }

        async def read_metrics():
            return await aggregator.get_fleet_metrics()

        # Run multiple concurrent reads
        tasks = [read_metrics() for _ in range(10)]
        results = await asyncio.gather(*tasks)

        # All should return same metrics
        for metrics in results:
            assert metrics.avg_cpu == 50.0

    async def test_concurrent_status_and_alerts(self):
        """Concurrent status and alert reads should be safe."""
        manager = DeviceManager()
        aggregator = FleetAggregator(manager)

        device = await manager.add_device(host="192.168.1.100")
        aggregator._device_metrics[device.id] = {
            "cpu_percent": 50.0,
            "mem_percent": 60.0,
            "online": True,
        }
        aggregator._device_alerts[device.id] = [
            {"id": "a1", "timestamp": 1000.0, "level": "info"}
        ]

        async def operations():
            status = await aggregator.get_fleet_status()
            alerts = await aggregator.get_all_alerts()
            metrics = await aggregator.get_fleet_metrics()
            return (status, alerts, metrics)

        tasks = [operations() for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # All should complete without error
        assert len(results) == 5
        for status, alerts, metrics in results:
            assert len(status) == 1
            assert len(alerts) == 1
