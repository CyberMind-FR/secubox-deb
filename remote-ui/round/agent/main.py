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

# Add agent directory to path for imports when run as script
sys.path.insert(0, str(Path(__file__).parent))

from config import load_config, Config, DEFAULT_CONFIG_PATH, get_active_secubox
from device_manager import DeviceManager
from metrics_bridge import MetricsBridge
from command_handler import create_command_client, WebSocketClient, CommandHandler

log = logging.getLogger(__name__)

# Default paths
SOCKET_PATH = Path("/run/secubox-eye/metrics.sock")
PID_FILE = Path("/run/secubox-eye/agent.pid")


class EyeAgent:
    """
    Main Eye Remote agent.

    Coordinates:
    - DeviceManager: SecuBox HTTP connections (polling metrics)
    - MetricsBridge: Dashboard communication (Unix socket)
    - CommandHandler: WebSocket bidirectionnel pour commandes
    - Polling loop: Regular metrics updates
    """

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.config: Optional[Config] = None
        self.device_manager: Optional[DeviceManager] = None
        self.metrics_bridge: Optional[MetricsBridge] = None
        self.ws_client: Optional[WebSocketClient] = None
        self.command_handler: Optional[CommandHandler] = None
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._bridge_task: Optional[asyncio.Task] = None
        self._ws_task: Optional[asyncio.Task] = None

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

        # Connect to SecuBox (HTTP pour polling)
        await self.device_manager.connect()

        # Creer le client WebSocket pour les commandes
        await self._setup_websocket_client()

        # Start services
        self._running = True
        self._bridge_task = asyncio.create_task(self.metrics_bridge.start())
        self._poll_task = asyncio.create_task(self._poll_loop())

        # Demarrer le client WebSocket si configure
        if self.ws_client:
            self._ws_task = asyncio.create_task(self._websocket_loop())

        # Write PID file
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()))

        log.info("Agent started")

        # Wait for shutdown - collecter toutes les taches
        tasks = [self._bridge_task, self._poll_task]
        if self._ws_task:
            tasks.append(self._ws_task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _setup_websocket_client(self):
        """
        Configurer le client WebSocket pour les commandes.

        Utilise le SecuBox actif et le token configure.
        """
        if not self.config:
            return

        active_sb = get_active_secubox(self.config)
        if not active_sb:
            log.warning("Pas de SecuBox actif - WebSocket desactive")
            return

        if not active_sb.token:
            log.warning("Pas de token configure - WebSocket desactive")
            return

        # Creer le client et handler
        self.ws_client, self.command_handler = create_command_client(
            host=active_sb.host,
            device_id=self.config.device.id,
            token=active_sb.token,
            port=8000,
            ssl=False
        )

        # Configurer les callbacks
        self.ws_client.on_connect(self._on_ws_connect)
        self.ws_client.on_disconnect(self._on_ws_disconnect)
        self.ws_client.on_error(self._on_ws_error)

        # Callback pour actions sur SecuBox (lockdown, etc.)
        self.command_handler.set_secubox_action_callback(self._handle_secubox_action)

        log.info("Client WebSocket configure pour %s", active_sb.host)

    async def _on_ws_connect(self):
        """Callback quand WebSocket connecte."""
        log.info("WebSocket connecte au SecuBox")
        # Envoyer le statut initial
        if self.ws_client:
            await self.ws_client.send_status({
                "state": "ready",
                "firmware": "2.0.0",
                "device_name": self.config.device.name if self.config else "Eye Remote"
            })

    async def _on_ws_disconnect(self):
        """Callback quand WebSocket deconnecte."""
        log.info("WebSocket deconnecte du SecuBox")

    async def _on_ws_error(self, error: Exception):
        """Callback sur erreur WebSocket."""
        log.error("Erreur WebSocket: %s", error)

    async def _handle_secubox_action(self, action: str, params: dict) -> dict:
        """
        Gerer les actions sur le SecuBox (lockdown, etc.).

        Ces actions sont relayees via l'API HTTP du SecuBox.

        Args:
            action: Type d'action (lockdown, etc.)
            params: Parametres de l'action

        Returns:
            Resultat de l'action
        """
        if not self.device_manager or not self.device_manager.active_secubox:
            return {"success": False, "error": "Pas de SecuBox connecte"}

        # Pour l'instant, on log l'action
        # TODO: Implementer les appels API correspondants
        log.info("Action SecuBox: %s params=%s", action, params)

        if action == "lockdown":
            enable = params.get("action") == "enable"
            log.info("Lockdown %s", "active" if enable else "desactive")
            return {
                "success": True,
                "message": f"Lockdown {'active' if enable else 'desactive'}"
            }

        return {"success": False, "error": f"Action inconnue: {action}"}

    async def _websocket_loop(self):
        """Boucle du client WebSocket avec reconnexion."""
        if not self.ws_client:
            return

        try:
            await self.ws_client.run()
        except asyncio.CancelledError:
            log.debug("WebSocket loop annulee")
        except Exception as e:
            log.error("Erreur WebSocket loop: %s", e)
        finally:
            if self.ws_client:
                await self.ws_client.stop()

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

        # Envoyer aussi via WebSocket si connecte
        if self.ws_client and self.ws_client.is_connected:
            asyncio.create_task(self._send_metrics_ws(metrics))

    async def _send_metrics_ws(self, metrics: dict):
        """Envoyer les metriques via WebSocket."""
        if self.ws_client:
            try:
                await self.ws_client.send_metrics(metrics)
            except Exception as e:
                log.debug("Erreur envoi metriques WS: %s", e)

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

        # Arreter le WebSocket
        if self.ws_client:
            await self.ws_client.stop()

        if self._ws_task:
            self._ws_task.cancel()
            try:
                await self._ws_task
            except asyncio.CancelledError:
                pass

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
