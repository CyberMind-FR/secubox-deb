"""
SecuBox Eye Remote — Metrics Bridge
Unix socket server that feeds metrics to the dashboard.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = Path("/run/secubox-eye/metrics.sock")


@dataclass
class MetricsBridge:
    """
    Unix socket server for sharing metrics with dashboard.

    The dashboard connects and reads the latest metrics as JSON.
    Connection is stateless - each read gets current state.
    """
    socket_path: Path = DEFAULT_SOCKET_PATH

    _metrics: dict = field(default_factory=dict)
    _secubox_name: str = ""
    _secubox_host: str = ""
    _transport: str = "sim"
    _timestamp: str = ""
    _server: Optional[asyncio.Server] = None
    _running: bool = False

    def update_metrics(
        self,
        metrics: dict,
        secubox_name: str = "",
        transport: str = "sim",
        secubox_host: str = ""
    ):
        """
        Update the current metrics.

        Args:
            metrics: Dict with cpu_percent, mem_percent, etc.
            secubox_name: Name of the active SecuBox
            transport: Transport type (otg, wifi, sim)
            secubox_host: Host address
        """
        self._metrics = metrics
        self._secubox_name = secubox_name
        self._secubox_host = secubox_host
        self._transport = transport
        self._timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def get_payload(self) -> dict:
        """
        Get the full payload for clients.

        Returns:
            Dict with secubox info, metrics, and timestamp
        """
        return {
            "secubox": {
                "name": self._secubox_name,
                "host": self._secubox_host,
                "transport": self._transport,
            },
            "metrics": self._metrics,
            "alerts": {
                "global_level": "nominal",
                "items": []
            },
            "timestamp": self._timestamp,
        }

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle a client connection."""
        try:
            payload = self.get_payload()
            data = json.dumps(payload).encode()
            writer.write(data)
            await writer.drain()
        except Exception as e:
            log.debug("Client error: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        """Start the Unix socket server."""
        # Ensure directory exists
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket
        if self.socket_path.exists():
            self.socket_path.unlink()

        self._running = True
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.socket_path)
        )

        # Set permissions (world-readable for dashboard)
        self.socket_path.chmod(0o666)

        log.info("Metrics bridge listening on %s", self.socket_path)

        async with self._server:
            await self._server.serve_forever()

    def stop(self):
        """Stop the server."""
        self._running = False
        if self._server:
            self._server.close()
