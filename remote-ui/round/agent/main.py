"""
SecuBox Eye Remote — Agent Main
Entry point for the Eye Remote agent service.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from typing import Optional

from .config import load_config, Config, DEFAULT_CONFIG_PATH
from .device_manager import DeviceManager
from .metrics_bridge import MetricsBridge

log = logging.getLogger(__name__)

# Default paths
SOCKET_PATH = Path("/run/secubox-eye/metrics.sock")
PID_FILE = Path("/run/secubox-eye/agent.pid")


class EyeAgent:
    """
    Main Eye Remote agent.

    Coordinates:
    - DeviceManager: SecuBox connections
    - MetricsBridge: Dashboard communication
    - Polling loop: Regular metrics updates
    """

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.config: Optional[Config] = None
        self.device_manager: Optional[DeviceManager] = None
        self.metrics_bridge: Optional[MetricsBridge] = None
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._bridge_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the agent."""
        log.info("Starting Eye Remote Agent v2.0.0")

        # Load config
        try:
            self.config = load_config(self.config_path)
            log.info("Loaded config: device=%s, secuboxes=%d",
                     self.config.device.id, len(self.config.secuboxes))
        except Exception as e:
            log.error("Failed to load config: %s", e)
            sys.exit(1)

        # Create components
        self.device_manager = DeviceManager(self.config)
        self.metrics_bridge = MetricsBridge(socket_path=SOCKET_PATH)

        # Wire up metrics updates
        self.device_manager.add_listener(self._on_metrics_update)

        # Connect to SecuBox
        await self.device_manager.connect()

        # Start services
        self._running = True
        self._bridge_task = asyncio.create_task(self.metrics_bridge.start())
        self._poll_task = asyncio.create_task(self._poll_loop())

        # Write PID file
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()))

        log.info("Agent started")

        # Wait for shutdown
        await asyncio.gather(self._bridge_task, self._poll_task, return_exceptions=True)

    def _on_metrics_update(self, metrics: dict, secubox_name: str, transport: str):
        """Handle metrics update from device manager."""
        if self.metrics_bridge and self.device_manager:
            secubox_host = ""
            if self.device_manager.active_secubox:
                secubox_host = self.device_manager.active_secubox.host
            self.metrics_bridge.update_metrics(
                metrics=metrics,
                secubox_name=secubox_name,
                transport=transport,
                secubox_host=secubox_host
            )

    async def _poll_loop(self):
        """Main polling loop."""
        while self._running:
            if self.device_manager:
                try:
                    await self.device_manager.poll_metrics()
                except Exception as e:
                    log.warning("Poll error: %s", e)

            # Get poll interval from active config
            interval = 2.0
            if self.device_manager and self.device_manager.active_secubox:
                interval = self.device_manager.active_secubox.poll_interval

            await asyncio.sleep(interval)

    async def stop(self):
        """Stop the agent."""
        log.info("Stopping agent...")
        self._running = False

        if self._poll_task:
            self._poll_task.cancel()

        if self.metrics_bridge:
            self.metrics_bridge.stop()

        if self._bridge_task:
            self._bridge_task.cancel()

        if self.device_manager:
            await self.device_manager.close()

        # Remove PID file
        if PID_FILE.exists():
            PID_FILE.unlink()

        log.info("Agent stopped")


async def main():
    """Main entry point."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Parse args
    config_path = DEFAULT_CONFIG_PATH
    if len(sys.argv) > 1:
        config_path = Path(sys.argv[1])

    agent = EyeAgent(config_path)

    # Handle signals
    loop = asyncio.get_running_loop()

    def handle_signal():
        asyncio.create_task(agent.stop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    await agent.start()


def run():
    """Run the agent."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
