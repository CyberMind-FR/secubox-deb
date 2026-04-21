"""Tests for SecuBox HTTP client."""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.fixture
def mock_metrics_response():
    """Create a mock metrics data."""
    return {
        "cpu_percent": 34.5,
        "mem_percent": 67.2,
        "disk_percent": 45.0,
        "wifi_rssi": -55,
        "load_avg_1": 0.82,
        "cpu_temp": 52.3,
        "uptime_seconds": 86400,
        "hostname": "secubox-lab",
        "modules_active": ["AUTH", "WALL", "BOOT"]
    }


@pytest.mark.asyncio
async def test_fetch_metrics_success(mock_metrics_response):
    """Should fetch and parse metrics from SecuBox API."""
    from agent.secubox_client import SecuBoxClient

    # Create mock response
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=mock_metrics_response)

    # Create a proper context manager mock
    mock_context_manager = MagicMock()
    mock_context_manager.__aenter__ = AsyncMock(return_value=mock_response)
    mock_context_manager.__aexit__ = AsyncMock(return_value=None)

    # Mock the session
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_context_manager)
    mock_session.closed = False
    mock_session.close = AsyncMock()

    with patch('agent.secubox_client.aiohttp.ClientSession', return_value=mock_session):
        client = SecuBoxClient(host="10.55.0.1", token="test-token")
        metrics = await client.fetch_metrics()

        assert metrics["cpu_percent"] == 34.5
        assert metrics["hostname"] == "secubox-lab"
        assert "AUTH" in metrics["modules_active"]

        await client.close()


@pytest.mark.asyncio
async def test_fetch_metrics_with_fallback():
    """Should try fallback host if primary fails."""
    from agent.secubox_client import SecuBoxClient

    call_count = 0

    def create_mock_context(url, headers=None, **kwargs):
        nonlocal call_count
        call_count += 1

        mock_cm = MagicMock()
        if "10.55.0.1" in url:
            # Primary fails
            mock_cm.__aenter__ = AsyncMock(side_effect=Exception("Connection refused"))
        else:
            # Fallback succeeds
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"cpu_percent": 50.0})
            mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        return mock_cm

    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=create_mock_context)
    mock_session.closed = False
    mock_session.close = AsyncMock()

    with patch('agent.secubox_client.aiohttp.ClientSession', return_value=mock_session):
        client = SecuBoxClient(
            host="10.55.0.1",
            token="test-token",
            fallback="secubox.local"
        )
        metrics = await client.fetch_metrics()

        assert metrics["cpu_percent"] == 50.0
        assert call_count >= 2  # Tried both hosts

        await client.close()


@pytest.mark.asyncio
async def test_client_uses_bearer_token():
    """Should include device token in Authorization header."""
    from agent.secubox_client import SecuBoxClient

    captured_headers = {}

    def capture_get(url, headers=None, **kwargs):
        nonlocal captured_headers
        captured_headers = headers or {}

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"cpu_percent": 10.0})

        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        return mock_cm

    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=capture_get)
    mock_session.closed = False
    mock_session.close = AsyncMock()

    with patch('agent.secubox_client.aiohttp.ClientSession', return_value=mock_session):
        client = SecuBoxClient(host="10.55.0.1", token="my-secret-token")
        await client.fetch_metrics()

        assert "Authorization" in captured_headers
        assert captured_headers["Authorization"] == "Bearer my-secret-token"

        await client.close()


@pytest.mark.asyncio
async def test_check_health_success():
    """Should return True when health endpoint responds 200."""
    from agent.secubox_client import SecuBoxClient

    mock_response = AsyncMock()
    mock_response.status = 200

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_cm)
    mock_session.closed = False
    mock_session.close = AsyncMock()

    with patch('agent.secubox_client.aiohttp.ClientSession', return_value=mock_session):
        client = SecuBoxClient(host="10.55.0.1", token="test-token")
        result = await client.check_health()

        assert result is True
        await client.close()


@pytest.mark.asyncio
async def test_check_health_failure():
    """Should return False when both hosts fail."""
    from agent.secubox_client import SecuBoxClient

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(side_effect=Exception("Connection refused"))
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_cm)
    mock_session.closed = False
    mock_session.close = AsyncMock()

    with patch('agent.secubox_client.aiohttp.ClientSession', return_value=mock_session):
        client = SecuBoxClient(host="10.55.0.1", token="test-token")
        result = await client.check_health()

        assert result is False
        await client.close()


@pytest.mark.asyncio
async def test_transport_property_otg():
    """Should return 'otg' for OTG network addresses."""
    from agent.secubox_client import SecuBoxClient

    client = SecuBoxClient(host="10.55.0.1", token="test")
    assert client.transport == "otg"


@pytest.mark.asyncio
async def test_transport_property_wifi():
    """Should return 'wifi' for non-OTG addresses."""
    from agent.secubox_client import SecuBoxClient

    client = SecuBoxClient(host="secubox.local", token="test")
    assert client.transport == "wifi"


@pytest.mark.asyncio
async def test_base_url_adds_port():
    """Should add default port 8000 if not specified."""
    from agent.secubox_client import SecuBoxClient

    client = SecuBoxClient(host="10.55.0.1", token="test")
    assert client.base_url == "http://10.55.0.1:8000"


@pytest.mark.asyncio
async def test_base_url_preserves_port():
    """Should preserve port if already specified."""
    from agent.secubox_client import SecuBoxClient

    client = SecuBoxClient(host="10.55.0.1:9000", token="test")
    assert client.base_url == "http://10.55.0.1:9000"


@pytest.mark.asyncio
async def test_base_url_preserves_scheme():
    """Should preserve https scheme if specified."""
    from agent.secubox_client import SecuBoxClient

    client = SecuBoxClient(host="https://secubox.example.com:443", token="test")
    assert client.base_url == "https://secubox.example.com:443"


@pytest.mark.asyncio
async def test_connection_error_when_both_fail():
    """Should raise ConnectionError when both primary and fallback fail."""
    from agent.secubox_client import SecuBoxClient

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(side_effect=Exception("Connection refused"))
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_cm)
    mock_session.closed = False
    mock_session.close = AsyncMock()

    with patch('agent.secubox_client.aiohttp.ClientSession', return_value=mock_session):
        client = SecuBoxClient(
            host="10.55.0.1",
            token="test-token",
            fallback="secubox.local"
        )

        with pytest.raises(ConnectionError) as exc_info:
            await client.fetch_metrics()

        assert "10.55.0.1" in str(exc_info.value)
        assert "secubox.local" in str(exc_info.value)
        await client.close()


@pytest.mark.asyncio
async def test_current_host_switches_on_fallback():
    """Should update current_host when using fallback."""
    from agent.secubox_client import SecuBoxClient

    client = SecuBoxClient(
        host="10.55.0.1",
        token="test",
        fallback="secubox.local"
    )

    # Initially primary
    assert client.current_host == "10.55.0.1"

    # Simulate fallback mode
    client._using_fallback = True
    assert client.current_host == "secubox.local"


@pytest.mark.asyncio
async def test_close_session():
    """Should close the HTTP session properly."""
    from agent.secubox_client import SecuBoxClient

    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.close = AsyncMock()

    with patch('agent.secubox_client.aiohttp.ClientSession', return_value=mock_session):
        client = SecuBoxClient(host="10.55.0.1", token="test")
        # Force session creation
        await client._get_session()

        # Close it
        await client.close()

        mock_session.close.assert_called_once()
        assert client._session is None
