"""Tests for device registry."""
import pytest
import tempfile
from pathlib import Path
import sys

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_registry_add_device():
    """Should add a device to registry."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice, DeviceScope

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        device = PairedDevice(
            device_id="eye-001",
            name="Test Eye",
            token_hash="sha256:abc123",
            scopes=[DeviceScope.METRICS_READ]
        )

        registry.add_device(device)

        retrieved = registry.get_device("eye-001")
        assert retrieved is not None
        assert retrieved.name == "Test Eye"


def test_registry_persists_to_file():
    """Registry should persist devices to JSON file."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice

    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir) / "devices.json"

        # Create and save
        registry1 = DeviceRegistry(storage_path=storage_path)
        registry1.add_device(PairedDevice(
            device_id="eye-002",
            name="Persisted Eye",
            token_hash="sha256:def456"
        ))

        # Load in new instance
        registry2 = DeviceRegistry(storage_path=storage_path)

        device = registry2.get_device("eye-002")
        assert device is not None
        assert device.name == "Persisted Eye"


def test_registry_remove_device():
    """Should remove a device from registry."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        registry.add_device(PairedDevice(
            device_id="eye-003",
            name="To Remove",
            token_hash="sha256:ghi789"
        ))

        assert registry.get_device("eye-003") is not None

        registry.remove_device("eye-003")

        assert registry.get_device("eye-003") is None


def test_registry_list_devices():
    """Should list all devices."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        registry.add_device(PairedDevice(device_id="eye-a", name="A", token_hash="h1"))
        registry.add_device(PairedDevice(device_id="eye-b", name="B", token_hash="h2"))

        devices = registry.list_devices()
        assert len(devices) == 2


def test_registry_update_last_seen():
    """Should update device last_seen timestamp."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice, TransportType

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        registry.add_device(PairedDevice(
            device_id="eye-004",
            name="Update Test",
            token_hash="sha256:jkl012"
        ))

        device_before = registry.get_device("eye-004")
        assert device_before.last_seen is None
        assert device_before.transport == TransportType.NONE

        registry.update_last_seen("eye-004", transport="wifi")

        device_after = registry.get_device("eye-004")
        assert device_after.last_seen is not None
        assert device_after.transport == TransportType.WIFI


def test_registry_validate_token():
    """Should validate device token."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        registry.add_device(PairedDevice(
            device_id="eye-005",
            name="Token Test",
            token_hash="sha256:secret123"
        ))

        assert registry.validate_token("eye-005", "sha256:secret123") is True
        assert registry.validate_token("eye-005", "sha256:wrong") is False
        assert registry.validate_token("nonexistent", "sha256:secret123") is False


def test_registry_get_nonexistent_device():
    """Should return None for nonexistent device."""
    from core.device_registry import DeviceRegistry

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        assert registry.get_device("nonexistent") is None


def test_registry_remove_nonexistent_device():
    """Should return False when removing nonexistent device."""
    from core.device_registry import DeviceRegistry

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        result = registry.remove_device("nonexistent")
        assert result is False
