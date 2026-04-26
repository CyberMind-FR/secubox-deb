"""
SecuBox Eye Remote — Tests for SecuBox Remote Control Client
Unit tests for the async HTTP client that communicates with SecuBox devices.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx


@pytest.fixture
def mock_metrics_response():
    """Sample metrics response from SecuBox API."""
    return {
        "cpu_percent": 34.5,
        "mem_percent": 67.2,
        "disk_percent": 45.0,
        "load_avg": 0.82,
        "temp": 52.3,
        "wifi_rssi": -55,
        "uptime_seconds": 86400,
    }


@pytest.fixture
def mock_modules_response():
    """Sample modules response from SecuBox API."""
    return {
        "modules": [
            {"name": "AUTH", "status": "active", "version": "2.0.0"},
            {"name": "WALL", "status": "active", "version": "2.0.0"},
            {"name": "BOOT", "status": "inactive", "version": "2.0.0"},
            {"name": "MIND", "status": "active", "version": "2.0.1"},
            {"name": "ROOT", "status": "error", "version": "2.0.0"},
            {"name": "MESH", "status": "active", "version": "2.0.0"},
        ]
    }


@pytest.fixture
def mock_alerts_response():
    """Sample alerts response from SecuBox API."""
    return {
        "alerts": [
            {
                "id": "alert-001",
                "level": "warn",
                "module": "ROOT",
                "message": "High CPU temperature detected",
                "timestamp": 1714100000.0,
            },
            {
                "id": "alert-002",
                "level": "critical",
                "module": "AUTH",
                "message": "Multiple authentication failures",
                "timestamp": 1714100100.0,
            },
        ]
    }


def create_mock_httpx_client(response_data=None, status_code=200, side_effect=None):
    """
    Create a mock httpx.AsyncClient instance.

    Args:
        response_data: JSON data to return from responses
        status_code: HTTP status code
        side_effect: Exception to raise
    """
    mock_client = MagicMock()
    mock_client.headers = httpx.Headers()

    if side_effect:
        mock_client.get = AsyncMock(side_effect=side_effect)
        mock_client.request = AsyncMock(side_effect=side_effect)
        mock_client.post = AsyncMock(side_effect=side_effect)
    else:
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = response_data or {}
        mock_response.raise_for_status = MagicMock()

        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client.post = AsyncMock(return_value=mock_response)

    mock_client.aclose = AsyncMock()
    return mock_client


@pytest.mark.asyncio
async def test_secubox_client_init():
    """Should initialize client with correct base URL and timeout."""
    from agent.secubox.remote_control import SecuBoxClient

    client = SecuBoxClient(host="10.55.0.1", port=8000, timeout=5.0)

    assert client.base_url == "http://10.55.0.1:8000"
    assert client.timeout == 5.0
    assert client._token is None

    await client.close()


@pytest.mark.asyncio
async def test_secubox_client_init_with_token():
    """Should initialize client with authentication token."""
    from agent.secubox.remote_control import SecuBoxClient

    client = SecuBoxClient(host="10.55.0.1", token="my-jwt-token")

    assert client._token == "my-jwt-token"

    await client.close()


@pytest.mark.asyncio
async def test_connect_success():
    """Should return True when health endpoint is reachable."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client({"status": "ok"}, status_code=200)

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        result = await client.connect()

        assert result is True
        mock_client.get.assert_called_once()

        await client.close()


@pytest.mark.asyncio
async def test_connect_failure():
    """Should return False when health endpoint is unreachable."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client(
        side_effect=httpx.ConnectError("Connection refused")
    )

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        result = await client.connect()

        assert result is False

        await client.close()


@pytest.mark.asyncio
async def test_get_metrics(mock_metrics_response):
    """Should fetch and parse metrics from SecuBox API."""
    from agent.secubox.remote_control import SecuBoxClient, SecuBoxMetrics

    mock_client = create_mock_httpx_client(mock_metrics_response)

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        metrics = await client.get_metrics()

        assert isinstance(metrics, SecuBoxMetrics)
        assert metrics.cpu_percent == 34.5
        assert metrics.mem_percent == 67.2
        assert metrics.disk_percent == 45.0
        assert metrics.load_avg == 0.82
        assert metrics.temp == 52.3
        assert metrics.wifi_rssi == -55
        assert metrics.uptime_seconds == 86400

        await client.close()


@pytest.mark.asyncio
async def test_get_modules(mock_modules_response):
    """Should fetch and parse module status from SecuBox API."""
    from agent.secubox.remote_control import SecuBoxClient, SecuBoxModule

    mock_client = create_mock_httpx_client(mock_modules_response)

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        modules = await client.get_modules()

        assert len(modules) == 6
        assert all(isinstance(m, SecuBoxModule) for m in modules)
        assert modules[0].name == "AUTH"
        assert modules[0].status == "active"
        assert modules[4].name == "ROOT"
        assert modules[4].status == "error"

        await client.close()


@pytest.mark.asyncio
async def test_get_alerts(mock_alerts_response):
    """Should fetch and parse alerts from SecuBox API."""
    from agent.secubox.remote_control import SecuBoxClient, SecuBoxAlert

    mock_client = create_mock_httpx_client(mock_alerts_response)

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        alerts = await client.get_alerts(limit=10)

        assert len(alerts) == 2
        assert all(isinstance(a, SecuBoxAlert) for a in alerts)
        assert alerts[0].id == "alert-001"
        assert alerts[0].level == "warn"
        assert alerts[1].level == "critical"

        await client.close()


@pytest.mark.asyncio
async def test_restart_module():
    """Should send POST request to restart a module."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client({"success": True})

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1", token="auth-token")
        result = await client.restart_module("AUTH")

        assert result is True
        mock_client.request.assert_called_once()
        call_args = mock_client.request.call_args
        assert call_args[0][0] == "POST"
        assert "/module/AUTH/restart" in call_args[0][1]

        await client.close()


@pytest.mark.asyncio
async def test_lockdown():
    """Should send POST request to trigger security lockdown."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client({"lockdown": True})

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1", token="auth-token")
        result = await client.lockdown()

        assert result is True
        mock_client.request.assert_called_once()
        call_args = mock_client.request.call_args
        assert call_args[0][0] == "POST"
        assert "/security/lockdown" in call_args[0][1]

        await client.close()


@pytest.mark.asyncio
async def test_health_check():
    """Should return True when health endpoint responds with 200."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client({"status": "healthy"})

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        result = await client.health_check()

        assert result is True

        await client.close()


@pytest.mark.asyncio
async def test_health_check_failure():
    """Should return False when health endpoint fails."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client(
        side_effect=httpx.TimeoutException("Timeout")
    )

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        result = await client.health_check()

        assert result is False

        await client.close()


@pytest.mark.asyncio
async def test_timeout_handling():
    """Should handle timeout errors gracefully."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client(
        side_effect=httpx.TimeoutException("Request timed out")
    )

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1", timeout=1.0)

        with pytest.raises(httpx.TimeoutException):
            await client.get_metrics()

        await client.close()


@pytest.mark.asyncio
async def test_authentication_header():
    """Should include Authorization header when token is provided."""
    from agent.secubox.remote_control import SecuBoxClient

    client = SecuBoxClient(host="10.55.0.1", token="my-secret-token")

    # Mock the AsyncClient constructor to capture headers
    original_init = httpx.AsyncClient.__init__
    captured_headers = {}

    def mock_init(self, *args, **kwargs):
        nonlocal captured_headers
        captured_headers = kwargs.get("headers", {})
        original_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, "__init__", mock_init):
        with patch.object(httpx.AsyncClient, "__aenter__", AsyncMock()):
            with patch.object(httpx.AsyncClient, "__aexit__", AsyncMock()):
                await client._ensure_client()

    assert "Authorization" in captured_headers
    assert captured_headers["Authorization"] == "Bearer my-secret-token"

    await client.close()


@pytest.mark.asyncio
async def test_connection_error_handling():
    """Should raise ConnectionError when API is unreachable."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client(
        side_effect=httpx.ConnectError("Connection refused")
    )

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")

        with pytest.raises(httpx.ConnectError):
            await client.get_metrics()

        await client.close()


@pytest.mark.asyncio
async def test_close_client():
    """Should close the HTTP client properly."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client({})

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")

        # Create client
        await client._ensure_client()
        assert client._client is not None

        # Close it
        await client.close()
        assert client._client is None
        mock_client.aclose.assert_called_once()


@pytest.mark.asyncio
async def test_get_metrics_missing_optional_fields():
    """Should handle missing optional fields in metrics response."""
    from agent.secubox.remote_control import SecuBoxClient, SecuBoxMetrics

    # Response without optional temp and wifi_rssi
    partial_response = {
        "cpu_percent": 50.0,
        "mem_percent": 60.0,
        "disk_percent": 40.0,
        "load_avg": 1.0,
        "uptime_seconds": 3600,
    }

    mock_client = create_mock_httpx_client(partial_response)

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        metrics = await client.get_metrics()

        assert isinstance(metrics, SecuBoxMetrics)
        assert metrics.cpu_percent == 50.0
        assert metrics.temp is None
        assert metrics.wifi_rssi is None

        await client.close()


@pytest.mark.asyncio
async def test_context_manager():
    """Should work as an async context manager."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client({"status": "ok"})

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        async with SecuBoxClient(host="10.55.0.1") as client:
            result = await client.health_check()
            assert result is True

        # Client should be closed after exiting context
        assert client._client is None


@pytest.mark.asyncio
async def test_request_uses_correct_url():
    """Should construct correct full URL for API requests."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client({"cpu_percent": 50.0})

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="192.168.1.100", port=9000)
        await client.get_metrics()

        call_args = mock_client.request.call_args
        full_url = call_args[0][1]
        assert full_url == "http://192.168.1.100:9000/api/v1/system/metrics"

        await client.close()


@pytest.mark.asyncio
async def test_get_alerts_with_limit_param():
    """Should pass limit parameter to alerts endpoint."""
    from agent.secubox.remote_control import SecuBoxClient

    mock_client = create_mock_httpx_client({"alerts": []})

    with patch(
        "agent.secubox.remote_control.httpx.AsyncClient", return_value=mock_client
    ):
        client = SecuBoxClient(host="10.55.0.1")
        await client.get_alerts(limit=25)

        call_args = mock_client.request.call_args
        assert call_args.kwargs.get("params") == {"limit": 25}

        await client.close()
