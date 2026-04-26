"""Tests for multi-SecuBox device manager."""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from agent.config import Config, DeviceConfig, SecuBoxConfig, SecuBoxesConfig


@pytest.fixture
def test_config():
    """Create test configuration with multiple SecuBoxes."""
    return Config(
        device=DeviceConfig(id="eye-test", name="Test Eye"),
        secuboxes=SecuBoxesConfig(
            primary="Primary",
            devices=[
                SecuBoxConfig(id="primary", name="Primary", host="10.55.0.1", token="token1", active=True),
                SecuBoxConfig(id="secondary", name="Secondary", host="192.168.1.100", token="token2", active=False),
            ]
        )
    )


@pytest.mark.asyncio
async def test_manager_connects_to_active_secubox(test_config):
    """Manager should connect to the active SecuBox."""
    from agent.device_manager import DeviceManager

    with patch('agent.device_manager.SecuBoxClient') as MockClient:
        mock_instance = AsyncMock()
        mock_instance.fetch_metrics = AsyncMock(return_value={"cpu_percent": 30.0})
        mock_instance.check_health = AsyncMock(return_value=True)
        MockClient.return_value = mock_instance

        manager = DeviceManager(test_config)
        await manager.connect()

        # Should have connected to Primary
        assert manager.active_secubox.name == "Primary"
        MockClient.assert_called_with(
            host="10.55.0.1",
            token="token1",
            fallback=None
        )


@pytest.mark.asyncio
async def test_manager_switches_secubox(test_config):
    """Manager should switch between SecuBoxes."""
    from agent.device_manager import DeviceManager

    with patch('agent.device_manager.SecuBoxClient') as MockClient:
        mock_instance = AsyncMock()
        mock_instance.fetch_metrics = AsyncMock(return_value={"cpu_percent": 50.0})
        mock_instance.check_health = AsyncMock(return_value=True)
        mock_instance.close = AsyncMock()
        MockClient.return_value = mock_instance

        manager = DeviceManager(test_config)
        await manager.connect()

        assert manager.active_secubox.name == "Primary"

        # Switch to Secondary
        await manager.switch_to("Secondary")

        assert manager.active_secubox.name == "Secondary"


@pytest.mark.asyncio
async def test_manager_polls_metrics(test_config):
    """Manager should poll metrics at configured interval."""
    from agent.device_manager import DeviceManager

    call_count = 0

    with patch('agent.device_manager.SecuBoxClient') as MockClient:
        async def mock_fetch():
            nonlocal call_count
            call_count += 1
            return {"cpu_percent": float(call_count * 10)}

        mock_instance = AsyncMock()
        mock_instance.fetch_metrics = mock_fetch
        mock_instance.check_health = AsyncMock(return_value=True)
        mock_instance.transport = "otg"
        MockClient.return_value = mock_instance

        manager = DeviceManager(test_config)
        await manager.connect()

        # Poll a few times
        for _ in range(3):
            metrics = await manager.poll_metrics()
            await asyncio.sleep(0.01)

        assert call_count == 3


def test_manager_lists_secuboxes(test_config):
    """Manager should list all configured SecuBoxes."""
    from agent.device_manager import DeviceManager

    manager = DeviceManager(test_config)
    secuboxes = manager.list_secuboxes()

    assert len(secuboxes) == 2
    assert secuboxes[0]["name"] == "Primary"
    assert secuboxes[0]["active"] is True
    assert secuboxes[1]["name"] == "Secondary"
    assert secuboxes[1]["active"] is False
