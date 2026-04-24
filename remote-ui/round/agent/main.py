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
from touch_handler import TouchHandler, create_touch_handler, Gesture
from menu_navigator import MenuNavigator, MenuMode
from radial_renderer import RadialRenderer
from action_executor import ActionExecutor
from local_api import LocalAPI

log = logging.getLogger(__name__)


def ensure_usb_network():
    """Ensure USB network interface is configured for OTG connection.

    The composite gadget creates two interfaces:
      - usb0: RNDIS (Windows compatible)
      - usb1: ECM (Linux/Mac compatible via cdc_ether driver)

    Linux hosts use cdc_ether which maps to usb1.
    We configure only usb1 to avoid asymmetric routing issues.
    """
    import subprocess
    import time

    for attempt in range(30):
        # Prefer usb1 (ECM) for Linux hosts
        if Path("/sys/class/net/usb1").exists():
            try:
                subprocess.run(["/sbin/ip", "addr", "flush", "dev", "usb1"],
                             capture_output=True, timeout=5)
                subprocess.run(["/sbin/ip", "addr", "add", "10.55.0.2/30", "dev", "usb1"],
                             capture_output=True, timeout=5)
                subprocess.run(["/sbin/ip", "link", "set", "usb1", "up"],
                             capture_output=True, timeout=5)
                log.info(f"usb1 (ECM) configured: 10.55.0.2/30 (attempt {attempt + 1})")
                return True
            except Exception as e:
                log.warning(f"Failed to configure usb1: {e}")
        # Fallback to usb0 (RNDIS) if usb1 not present
        elif Path("/sys/class/net/usb0").exists():
            try:
                subprocess.run(["/sbin/ip", "addr", "flush", "dev", "usb0"],
                             capture_output=True, timeout=5)
                subprocess.run(["/sbin/ip", "addr", "add", "10.55.0.2/30", "dev", "usb0"],
                             capture_output=True, timeout=5)
                subprocess.run(["/sbin/ip", "link", "set", "usb0", "up"],
                             capture_output=True, timeout=5)
                log.info(f"usb0 (RNDIS) configured: 10.55.0.2/30 (attempt {attempt + 1})")
                return True
            except Exception as e:
                log.warning(f"Failed to configure usb0: {e}")
        time.sleep(1)

    log.warning("No USB network interface found after 30 attempts")
    return False

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
        self.touch_handler: Optional[TouchHandler] = None
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._bridge_task: Optional[asyncio.Task] = None
        self._ws_task: Optional[asyncio.Task] = None
        self._touch_task: Optional[asyncio.Task] = None

        # Menu system components
        self.menu_navigator = MenuNavigator()
        self.radial_renderer = RadialRenderer()
        self.local_api = LocalAPI()
        self.action_executor = ActionExecutor(local_api=self.local_api)

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

        # Demarrer le gestionnaire de gestes tactiles
        await self._setup_touch_handler()

        # Write PID file
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()))

        log.info("Agent started")

        # Wait for shutdown - collecter toutes les taches
        tasks = [self._bridge_task, self._poll_task]
        if self._ws_task:
            tasks.append(self._ws_task)
        if self._touch_task:
            tasks.append(self._touch_task)

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

    async def _setup_touch_handler(self):
        """
        Configurer le gestionnaire de gestes tactiles.

        Cree le TouchHandler et configure les callbacks pour:
        - Changement de SecuBox (swipe gauche/droite)
        - Redemarrage de service (tap sur module)
        - Lockdown d'urgence (3-finger tap)
        - Toggle overlay info (swipe down)
        - Liste des devices (long press centre)
        """
        # Creer le handler avec les references aux composants
        self.touch_handler = create_touch_handler(
            device_manager=self.device_manager,
            ws_client=self.ws_client
        )

        # Configure touch handler with menu
        self.touch_handler.set_menu_navigator(self.menu_navigator)
        self.touch_handler.set_action_executor(self.action_executor)
        self.touch_handler.on_menu_render(self._render_menu)

        # State change callback
        self.menu_navigator.on_state_change(lambda s: self._render_menu())

        # Configurer les callbacks
        self.touch_handler.on_gesture(self._on_touch_gesture)
        self.touch_handler.on_secubox_switch(self._on_secubox_switch)
        self.touch_handler.on_overlay_toggle(self._on_overlay_toggle)
        self.touch_handler.on_device_list_toggle(self._on_device_list_toggle)

        # Demarrer le handler (non-bloquant)
        success = await self.touch_handler.start()
        if success:
            log.info("TouchHandler actif: %s", self.touch_handler.touch_device_name)
        else:
            log.warning("TouchHandler non demarre - mode tactile desactive")

    def _render_menu(self) -> None:
        """Render the menu to framebuffer."""
        if not self.radial_renderer or not self.menu_navigator:
            return

        try:
            image = self.radial_renderer.render(self.menu_navigator.state)
            self.radial_renderer.write_to_framebuffer()
        except Exception as e:
            log.error("Render error: %s", e)

    def _on_touch_gesture(self, gesture: Gesture, data: dict):
        """Callback generique pour les gestes tactiles."""
        log.debug("Geste tactile: %s data=%s", gesture.name, data)

    def _on_secubox_switch(self, name: str):
        """Callback quand on change de SecuBox via geste."""
        log.info("SecuBox change via geste: %s", name)
        # Mettre a jour le bridge avec le nouveau SecuBox
        if self.metrics_bridge and self.device_manager:
            secubox_host = ""
            if self.device_manager.active_secubox:
                secubox_host = self.device_manager.active_secubox.host
            # Le bridge sera mis a jour au prochain poll

    def _on_overlay_toggle(self, visible: bool):
        """Callback quand l'overlay info est toggle."""
        log.info("Overlay info: %s", "visible" if visible else "cache")
        # TODO: Signaler au dashboard fb_dashboard.py via le bridge

    def _on_device_list_toggle(self, visible: bool):
        """Callback quand la liste des devices est toggle."""
        log.info("Liste devices: %s", "visible" if visible else "cache")
        # TODO: Signaler au dashboard fb_dashboard.py via le bridge

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

        # Arreter le TouchHandler
        if self.touch_handler:
            await self.touch_handler.stop()

        if self._touch_task:
            self._touch_task.cancel()
            try:
                await self._touch_task
            except asyncio.CancelledError:
                pass

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

    # Ensure USB OTG network is configured
    ensure_usb_network()

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
