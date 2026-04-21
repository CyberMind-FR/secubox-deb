"""Tests for metrics bridge Unix socket server."""
import pytest
import asyncio
import json
import tempfile
from pathlib import Path


@pytest.mark.asyncio
async def test_bridge_serves_metrics():
    """Bridge should serve metrics over Unix socket."""
    from agent.metrics_bridge import MetricsBridge

    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = Path(tmpdir) / "metrics.sock"

        bridge = MetricsBridge(socket_path=sock_path)

        # Update with test metrics
        bridge.update_metrics({
            "cpu_percent": 42.0,
            "hostname": "test-secubox"
        }, secubox_name="Test", transport="otg")

        # Start server
        server_task = asyncio.create_task(bridge.start())
        await asyncio.sleep(0.1)  # Let server start

        # Connect as client
        reader, writer = await asyncio.open_unix_connection(str(sock_path))

        # Read metrics
        data = await reader.read(4096)
        metrics = json.loads(data.decode())

        assert metrics["metrics"]["cpu_percent"] == 42.0
        assert metrics["secubox"]["name"] == "Test"
        assert metrics["secubox"]["transport"] == "otg"

        writer.close()
        await writer.wait_closed()

        # Cleanup
        bridge.stop()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_bridge_handles_multiple_clients():
    """Bridge should handle multiple concurrent clients."""
    from agent.metrics_bridge import MetricsBridge

    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = Path(tmpdir) / "metrics.sock"

        bridge = MetricsBridge(socket_path=sock_path)
        bridge.update_metrics({"cpu_percent": 50.0}, "Lab", "wifi")

        server_task = asyncio.create_task(bridge.start())
        await asyncio.sleep(0.1)

        # Connect multiple clients
        async def read_metrics():
            reader, writer = await asyncio.open_unix_connection(str(sock_path))
            data = await reader.read(4096)
            writer.close()
            await writer.wait_closed()
            return json.loads(data.decode())

        results = await asyncio.gather(
            read_metrics(),
            read_metrics(),
            read_metrics()
        )

        for r in results:
            assert r["metrics"]["cpu_percent"] == 50.0

        bridge.stop()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
