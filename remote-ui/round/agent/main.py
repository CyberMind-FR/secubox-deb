# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote — Agent Main
Entry point for the Eye Remote agent service with full component integration.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

# Setup logging early for import debugging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
_import_log = logging.getLogger("eye-agent.imports")

# Add parent directory to path for package imports when run as script
_agent_dir = Path(__file__).parent
_parent_dir = _agent_dir.parent
if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))
if str(_agent_dir) not in sys.path:
    sys.path.insert(0, str(_agent_dir))


def _try_import(module_path: str, fallback_path: str, items: list) -> dict:
    """
    Try to import items from module_path, fallback to fallback_path.
    Returns dict of item_name -> imported_object or None.
    """
    result = {item: None for item in items}

    # Try agent.X path first
    try:
        mod = __import__(module_path, fromlist=items)
        for item in items:
            if hasattr(mod, item):
                result[item] = getattr(mod, item)
        _import_log.debug(f"Imported from {module_path}: {[k for k,v in result.items() if v]}")
        return result
    except ImportError as e:
        _import_log.debug(f"Could not import {module_path}: {e}")

    # Try direct path
    try:
        mod = __import__(fallback_path, fromlist=items)
        for item in items:
            if hasattr(mod, item):
                result[item] = getattr(mod, item)
        _import_log.debug(f"Imported from {fallback_path}: {[k for k,v in result.items() if v]}")
        return result
    except ImportError as e:
        _import_log.warning(f"Could not import {fallback_path}: {e}")

    return result


# Core config - required
_config = _try_import("agent.config", "config",
                      ["load_config", "Config", "DEFAULT_CONFIG_PATH", "get_active_secubox"])
load_config = _config["load_config"]
Config = _config["Config"]
DEFAULT_CONFIG_PATH = _config["DEFAULT_CONFIG_PATH"] or Path("/etc/secubox/eye-remote/config.toml")
get_active_secubox = _config["get_active_secubox"]

# Mode manager - required
_mode = _try_import("agent.mode_manager", "mode_manager", ["Mode", "ModeManager"])
Mode = _mode["Mode"]
ModeManager = _mode["ModeManager"]

# Failover - required
_failover = _try_import("agent.failover", "failover", ["FailoverMonitor", "FailoverState"])
FailoverMonitor = _failover["FailoverMonitor"]
FailoverState = _failover["FailoverState"]

# Display renderers - required
_display = _try_import("agent.display", "display",
                       ["DashboardRenderer", "LocalRenderer", "FlashRenderer",
                        "GatewayRenderer", "RenderContext"])
DashboardRenderer = _display["DashboardRenderer"]
LocalRenderer = _display["LocalRenderer"]
FlashRenderer = _display["FlashRenderer"]
GatewayRenderer = _display["GatewayRenderer"]
RenderContext = _display["RenderContext"]

# System controllers - optional
_system = _try_import("agent.system", "system",
                      ["WifiManager", "BluetoothManager", "DisplayController"])
WifiManager = _system["WifiManager"]
BluetoothManager = _system["BluetoothManager"]
DisplayController = _system["DisplayController"]

# SecuBox device management - optional
_secubox = _try_import("agent.secubox", "secubox", ["DeviceManager", "FleetAggregator"])
DeviceManager = _secubox["DeviceManager"]
FleetAggregator = _secubox["FleetAggregator"]

# Web server - optional
_web = _try_import("agent.web", "web", ["WebServer"])
WebServer = _web["WebServer"]

# Legacy device manager - optional (requires aiohttp)
_legacy = _try_import("agent.device_manager", "device_manager", ["DeviceManager"])
LegacyDeviceManager = _legacy.get("DeviceManager")

# Metrics bridge - optional
_metrics = _try_import("agent.metrics_bridge", "metrics_bridge", ["MetricsBridge"])
MetricsBridge = _metrics["MetricsBridge"]

# Command handler - optional
_cmd = _try_import("agent.command_handler", "command_handler",
                   ["create_command_client", "WebSocketClient", "CommandHandler"])
create_command_client = _cmd["create_command_client"]
WebSocketClient = _cmd["WebSocketClient"]
CommandHandler = _cmd["CommandHandler"]

# Touch handler - optional
_touch = _try_import("agent.touch_handler", "touch_handler",
                     ["TouchHandler", "create_touch_handler", "Gesture"])
TouchHandler = _touch["TouchHandler"]
create_touch_handler = _touch["create_touch_handler"]
Gesture = _touch["Gesture"]

# Menu system - optional
_menu = _try_import("agent.menu_navigator", "menu_navigator", ["MenuNavigator", "MenuMode"])
MenuNavigator = _menu["MenuNavigator"]
MenuMode = _menu["MenuMode"]

# Radial renderer - optional
_radial = _try_import("agent.radial_renderer", "radial_renderer", ["RadialRenderer"])
RadialRenderer = _radial["RadialRenderer"]

# Action executor - optional
_action = _try_import("agent.action_executor", "action_executor", ["ActionExecutor"])
ActionExecutor = _action["ActionExecutor"]

# Local API - optional
_local = _try_import("agent.local_api", "local_api", ["LocalAPI"])
LocalAPI = _local["LocalAPI"]

log = logging.getLogger(__name__)

# Version
VERSION = "2.1.0"

# Default paths
SOCKET_PATH = Path("/run/secubox-eye/metrics.sock")
PID_FILE = Path("/run/secubox-eye/agent.pid")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Eye Remote Swiss Army Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run with defaults
  %(prog)s -c /path/to/config.toml  # Use custom config
  %(prog)s --no-display             # Headless mode (web API only)
  %(prog)s --simulate               # Simulation mode for hardware
  %(prog)s -p 8081 -v               # Custom port with verbose logging
        """,
    )
    parser.add_argument(
        "--config", "-c",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Config file path (default: %(default)s)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        help="Web server port (default: %(default)s)",
    )
    parser.add_argument(
        "--no-display",
        action="store_true",
        help="Run without display (headless mode)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Use simulation mode for hardware",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose logging (DEBUG level)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser.parse_args()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with appropriate level and format."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Reduce noise from external libraries
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def ensure_usb_network() -> bool:
    """
    Ensure USB network interface is configured for OTG connection.

    The composite gadget creates two interfaces:
      - usb0: RNDIS (Windows compatible)
      - usb1: ECM (Linux/Mac compatible via cdc_ether driver)

    Linux hosts use cdc_ether which maps to usb1.
    We configure only usb1 to avoid asymmetric routing issues.
    """
    import subprocess

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


class EyeAgent:
    """
    Main Eye Remote agent with full component integration.

    Coordinates:
    - ModeManager: Operating mode state machine
    - FailoverMonitor: Connection monitoring and graceful degradation
    - DeviceManager: SecuBox HTTP connections (polling metrics)
    - FleetAggregator: Multi-SecuBox fleet management
    - MetricsBridge: Dashboard communication (Unix socket)
    - WebServer: HTTP API and control interface
    - DisplayEngine: Framebuffer rendering (HyperPixel 2.1 Round)
    - System controllers: WiFi, Bluetooth, Display
    - Touch/Menu: Radial menu navigation
    """

    def __init__(
        self,
        config_path: Path = DEFAULT_CONFIG_PATH,
        port: int = 8080,
        headless: bool = False,
        simulate: bool = False,
    ):
        self.config_path = config_path
        self.port = port
        self.headless = headless
        self.simulate = simulate

        # Core state
        self.config: Optional[Config] = None
        self._running = False
        self._shutdown_event = asyncio.Event()

        # Mode and connection management
        self.mode_manager = ModeManager()
        self.failover_monitor = FailoverMonitor()

        # System controllers
        self.wifi_manager = WifiManager()
        self.bluetooth_manager = BluetoothManager()
        self.display_controller = DisplayController()

        # SecuBox management
        self.device_manager: Optional[DeviceManager] = None
        self.fleet_aggregator: Optional[FleetAggregator] = None
        self.legacy_device_manager: Optional[LegacyDeviceManager] = None

        # Communication
        self.metrics_bridge: Optional[MetricsBridge] = None
        self.ws_client: Optional[WebSocketClient] = None
        self.command_handler: Optional[CommandHandler] = None
        self.web_server: Optional[WebServer] = None

        # Display rendering
        self.renderers: dict[Mode, DashboardRenderer | LocalRenderer | FlashRenderer | GatewayRenderer] = {}
        self._display_task: Optional[asyncio.Task] = None

        # Menu system
        self.touch_handler: Optional[TouchHandler] = None
        self.menu_navigator = MenuNavigator()
        self.radial_renderer = RadialRenderer()
        self.local_api = LocalAPI()
        self.action_executor = ActionExecutor(local_api=self.local_api)

        # Background tasks
        self._tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        """Start the agent with all components."""
        log.info(f"Starting Eye Remote Agent v{VERSION}")
        log.info(f"Headless: {self.headless}, Simulate: {self.simulate}")

        # Load configuration
        try:
            self.config = load_config(self.config_path)
            log.info(f"Loaded config: device={self.config.device.id}")
        except Exception as e:
            log.error(f"Failed to load config: {e}")
            self.config = Config()

        # Initialize USB network (for OTG mode)
        ensure_usb_network()

        # Initialize components in order
        await self._init_device_management()
        await self._init_communication()
        await self._init_web_server()
        await self._init_display()

        # Register mode change listener
        self.mode_manager.add_listener(self._on_mode_change)
        self.failover_monitor.add_listener(self._on_failover_change)

        # Start services
        self._running = True
        await self._start_services()

        # Write PID file
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()))

        log.info(f"Agent started - Web UI at http://0.0.0.0:{self.port}")

        # Wait for shutdown signal
        await self._shutdown_event.wait()

    async def _init_device_management(self) -> None:
        """Initialize SecuBox device management."""
        if not self.config:
            return

        # New device manager from secubox module
        self.device_manager = DeviceManager(self.config)

        # Legacy device manager for backward compatibility
        self.legacy_device_manager = LegacyDeviceManager(self.config)
        self.legacy_device_manager.add_listener(self._on_metrics_update)

        # Fleet aggregator for gateway mode (if multiple devices configured)
        if len(self.config.secuboxes.devices) > 1:
            self.fleet_aggregator = FleetAggregator(self.device_manager)
            log.info(f"Fleet aggregator initialized with {len(self.config.secuboxes.devices)} devices")

        # Connect to SecuBox
        await self.legacy_device_manager.connect()

    async def _init_communication(self) -> None:
        """Initialize communication channels."""
        # Metrics bridge (Unix socket for dashboard)
        self.metrics_bridge = MetricsBridge(socket_path=SOCKET_PATH)

        # WebSocket client for bidirectional commands
        await self._setup_websocket_client()

    async def _init_web_server(self) -> None:
        """Initialize web server with all controllers."""
        self.web_server = WebServer(
            host="0.0.0.0",
            port=self.port,
            mode_manager=self.mode_manager,
            failover_monitor=self.failover_monitor,
            config=self.config,
            wifi_manager=self.wifi_manager,
            bluetooth_manager=self.bluetooth_manager,
            display_controller=self.display_controller,
        )

    async def _init_display(self) -> None:
        """Initialize display renderers."""
        if self.headless:
            log.info("Headless mode - skipping display initialization")
            return

        # Initialize renderers for each mode
        self.renderers = {
            Mode.DASHBOARD: DashboardRenderer(),
            Mode.LOCAL: LocalRenderer(),
            Mode.FLASH: FlashRenderer(),
            Mode.GATEWAY: GatewayRenderer(),
        }

        # Initialize touch handler
        await self._setup_touch_handler()

        log.info("Display renderers initialized")

    async def _start_services(self) -> None:
        """Start all background services."""
        # Start metrics bridge
        if self.metrics_bridge:
            task = asyncio.create_task(self.metrics_bridge.start())
            self._tasks.append(task)

        # Start polling loop
        task = asyncio.create_task(self._poll_loop())
        self._tasks.append(task)

        # Start WebSocket client
        if self.ws_client:
            task = asyncio.create_task(self._websocket_loop())
            self._tasks.append(task)

        # Start failover monitor
        def api_check() -> bool:
            """Check if API is reachable."""
            if self.legacy_device_manager and self.legacy_device_manager.active_secubox:
                return True
            return False

        await self.failover_monitor.start_monitoring(api_check)

        # Start fleet aggregator (if in gateway mode)
        if self.fleet_aggregator:
            await self.fleet_aggregator.start()

        # Start web server
        if self.web_server:
            await self.web_server.start()

        # Start display loop (if not headless)
        if not self.headless:
            self._display_task = asyncio.create_task(self._display_loop())
            self._tasks.append(self._display_task)

            # Initial render
            self._render_display()

        # Determine initial mode based on API availability
        api_available = self.legacy_device_manager is not None and \
                       self.legacy_device_manager.active_secubox is not None
        await self.mode_manager.determine_initial_mode(api_available)

    async def _setup_websocket_client(self) -> None:
        """Configure WebSocket client for commands."""
        if not self.config:
            return

        active_sb = get_active_secubox(self.config)
        if not active_sb:
            log.warning("No active SecuBox - WebSocket disabled")
            return

        if not active_sb.token:
            log.warning("No token configured - WebSocket disabled")
            return

        self.ws_client, self.command_handler = create_command_client(
            host=active_sb.host,
            device_id=self.config.device.id,
            token=active_sb.token,
            port=8000,
            ssl=False,
        )

        self.ws_client.on_connect(self._on_ws_connect)
        self.ws_client.on_disconnect(self._on_ws_disconnect)
        self.ws_client.on_error(self._on_ws_error)
        self.command_handler.set_secubox_action_callback(self._handle_secubox_action)

        log.info(f"WebSocket client configured for {active_sb.host}")

    async def _setup_touch_handler(self) -> None:
        """Configure touch handler and menu system."""
        self.touch_handler = create_touch_handler(
            device_manager=self.legacy_device_manager,
            ws_client=self.ws_client,
        )

        success = await self.touch_handler.start()

        if success:
            log.info(f"TouchHandler active: {self.touch_handler.touch_device_name}")

            self.touch_handler.set_menu_navigator(self.menu_navigator)
            self.touch_handler.set_action_executor(self.action_executor)
            self.touch_handler.on_menu_render(lambda _: self._render_menu())

            self.menu_navigator.on_state_change(lambda _s: self._render_menu())

            self.touch_handler.on_gesture(self._on_touch_gesture)
            self.touch_handler.on_secubox_switch(self._on_secubox_switch)
            self.touch_handler.on_overlay_toggle(self._on_overlay_toggle)
            self.touch_handler.on_device_list_toggle(self._on_device_list_toggle)
        else:
            log.warning("TouchHandler not started - touch/menu disabled")
            self.menu_navigator.exit_to_dashboard()

    def _on_mode_change(self, old_mode: Mode, new_mode: Mode) -> None:
        """Handle mode transitions."""
        log.info(f"Mode changed: {old_mode.value} -> {new_mode.value}")
        if not self.headless:
            self._render_display()

    def _on_failover_change(
        self, old_state: FailoverState, new_state: FailoverState
    ) -> None:
        """Handle failover state changes."""
        log.info(f"Failover state: {old_state.value} -> {new_state.value}")

        # Auto-switch to Local mode on disconnect
        if new_state == FailoverState.DISCONNECTED:
            asyncio.create_task(self.mode_manager.set_mode(Mode.LOCAL))
        elif new_state == FailoverState.CONNECTED and \
             self.mode_manager.current_mode == Mode.LOCAL:
            # Restore Dashboard mode when connection returns
            asyncio.create_task(self.mode_manager.set_mode(Mode.DASHBOARD))

    def _on_metrics_update(
        self, metrics: dict, secubox_name: str, transport: str
    ) -> None:
        """Handle metrics update from device manager."""
        # Record success for failover monitor
        self.failover_monitor.record_success()

        # Update metrics bridge
        if self.metrics_bridge and self.legacy_device_manager:
            secubox_host = ""
            if self.legacy_device_manager.active_secubox:
                secubox_host = self.legacy_device_manager.active_secubox.host
            self.metrics_bridge.update_metrics(
                metrics=metrics,
                secubox_name=secubox_name,
                transport=transport,
                secubox_host=secubox_host,
            )

        # Update radial renderer
        if self.radial_renderer:
            self.radial_renderer.update_metrics(metrics)
            if self.menu_navigator and self.menu_navigator.state.mode == MenuMode.DASHBOARD:
                self._render_menu()

        # Re-render display if in dashboard mode
        if not self.headless and self.mode_manager.current_mode == Mode.DASHBOARD:
            self._render_display()

        # Send via WebSocket
        if self.ws_client and self.ws_client.is_connected:
            asyncio.create_task(self._send_metrics_ws(metrics))

    async def _send_metrics_ws(self, metrics: dict) -> None:
        """Send metrics via WebSocket."""
        if self.ws_client:
            try:
                await self.ws_client.send_metrics(metrics)
            except Exception as e:
                log.debug(f"WebSocket metrics send error: {e}")

    async def _poll_loop(self) -> None:
        """Main polling loop for metrics."""
        while self._running:
            if self.legacy_device_manager:
                try:
                    await self.legacy_device_manager.poll_metrics()
                except Exception as e:
                    log.warning(f"Poll error: {e}")
                    self.failover_monitor.update_state()

            # Get poll interval from active config
            interval = 2.0
            if self.legacy_device_manager and self.legacy_device_manager.active_secubox:
                interval = self.legacy_device_manager.active_secubox.poll_interval

            await asyncio.sleep(interval)

    async def _websocket_loop(self) -> None:
        """WebSocket client loop with reconnection."""
        if not self.ws_client:
            return

        try:
            await self.ws_client.run()
        except asyncio.CancelledError:
            log.debug("WebSocket loop cancelled")
        except Exception as e:
            log.error(f"WebSocket loop error: {e}")
        finally:
            if self.ws_client:
                await self.ws_client.stop()

    async def _display_loop(self) -> None:
        """Main display rendering loop at 30 FPS."""
        target_fps = 30
        frame_time = 1.0 / target_fps

        while self._running:
            try:
                start = time.monotonic()

                # Render current mode
                self._render_display()

                # Sleep for remaining frame time
                elapsed = time.monotonic() - start
                sleep_time = max(0, frame_time - elapsed)
                await asyncio.sleep(sleep_time)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Display loop error: {e}")
                await asyncio.sleep(1.0)

    def _render_display(self) -> None:
        """Render current display mode to framebuffer."""
        if self.headless:
            return

        mode = self.mode_manager.current_mode
        renderer = self.renderers.get(mode)

        if not renderer:
            log.warning(f"No renderer for mode: {mode}")
            return

        try:
            ctx = self._build_render_context()
            renderer.render(ctx)
            renderer.write_to_framebuffer()
        except Exception as e:
            log.error(f"Render error: {e}")

    def _render_menu(self) -> None:
        """Render menu overlay to framebuffer."""
        if not self.radial_renderer or not self.menu_navigator:
            return

        try:
            self.radial_renderer.render(self.menu_navigator.state)
            self.radial_renderer.write_to_framebuffer()
        except Exception as e:
            log.error(f"Menu render error: {e}")

    def _build_render_context(self) -> RenderContext:
        """Build render context from current state."""
        metrics = {}
        hostname = "eye-remote"
        uptime = 0
        secubox_name = ""

        if self.legacy_device_manager:
            if self.legacy_device_manager.active_secubox:
                secubox_name = self.legacy_device_manager.active_secubox.name
            # Get cached metrics
            metrics = getattr(self.legacy_device_manager, '_cached_metrics', {})
            hostname = metrics.get("hostname", hostname)
            uptime = metrics.get("uptime_seconds", uptime)

        # Map failover state to connection state string
        connection_state = "disconnected"
        fs = self.failover_monitor.state
        if fs == FailoverState.CONNECTED:
            connection_state = "connected"
        elif fs == FailoverState.STALE:
            connection_state = "stale"
        elif fs == FailoverState.DEGRADED:
            connection_state = "degraded"

        # Build device list for gateway mode (use cached data)
        devices = []
        if self.fleet_aggregator:
            # Access cached device statuses synchronously
            for device_id, device_data in self.fleet_aggregator._device_metrics.items():
                devices.append({
                    'name': device_id,
                    'online': device_data.get('online', False),
                })

        return RenderContext(
            mode=self.mode_manager.current_mode.value,
            connection_state=connection_state,
            metrics=metrics,
            hostname=hostname,
            uptime_seconds=uptime,
            secubox_name=secubox_name,
            devices=devices,
        )

    # Touch/gesture callbacks
    def _on_touch_gesture(self, gesture: Gesture, data: dict) -> None:
        """Handle touch gesture."""
        log.debug(f"Touch gesture: {gesture.name} data={data}")

    def _on_secubox_switch(self, name: str) -> None:
        """Handle SecuBox switch via gesture."""
        log.info(f"SecuBox switched via gesture: {name}")

    def _on_overlay_toggle(self, visible: bool) -> None:
        """Handle overlay toggle."""
        log.info(f"Overlay: {'visible' if visible else 'hidden'}")

    def _on_device_list_toggle(self, visible: bool) -> None:
        """Handle device list toggle."""
        log.info(f"Device list: {'visible' if visible else 'hidden'}")

    # WebSocket callbacks
    async def _on_ws_connect(self) -> None:
        """Handle WebSocket connection."""
        log.info("WebSocket connected to SecuBox")
        if self.ws_client:
            await self.ws_client.send_status({
                "state": "ready",
                "firmware": VERSION,
                "device_name": self.config.device.name if self.config else "Eye Remote",
            })

    async def _on_ws_disconnect(self) -> None:
        """Handle WebSocket disconnection."""
        log.info("WebSocket disconnected from SecuBox")

    async def _on_ws_error(self, error: Exception) -> None:
        """Handle WebSocket error."""
        log.error(f"WebSocket error: {error}")

    async def _handle_secubox_action(self, action: str, params: dict) -> dict:
        """Handle SecuBox action (lockdown, etc.)."""
        if not self.legacy_device_manager or not self.legacy_device_manager.active_secubox:
            return {"success": False, "error": "No SecuBox connected"}

        log.info(f"SecuBox action: {action} params={params}")

        if action == "lockdown":
            enable = params.get("action") == "enable"
            log.info(f"Lockdown {'enabled' if enable else 'disabled'}")
            return {"success": True, "message": f"Lockdown {'enabled' if enable else 'disabled'}"}

        return {"success": False, "error": f"Unknown action: {action}"}

    async def stop(self) -> None:
        """Stop the agent gracefully."""
        log.info("Stopping agent...")
        self._running = False
        self._shutdown_event.set()

        # Stop touch handler
        if self.touch_handler:
            await self.touch_handler.stop()

        # Stop WebSocket
        if self.ws_client:
            await self.ws_client.stop()

        # Stop failover monitor
        await self.failover_monitor.stop_monitoring()

        # Stop fleet aggregator
        if self.fleet_aggregator:
            await self.fleet_aggregator.stop()

        # Stop web server
        if self.web_server:
            await self.web_server.stop()

        # Stop metrics bridge
        if self.metrics_bridge:
            self.metrics_bridge.stop()

        # Close device manager
        if self.legacy_device_manager:
            await self.legacy_device_manager.close()

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Remove PID file
        if PID_FILE.exists():
            PID_FILE.unlink()

        log.info("Agent stopped")


async def wait_for_shutdown() -> None:
    """Wait for shutdown signal in headless mode."""
    shutdown = asyncio.Event()

    def signal_handler():
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    await shutdown.wait()


async def main() -> None:
    """Main entry point."""
    args = parse_args()
    setup_logging(args.verbose)

    agent = EyeAgent(
        config_path=args.config,
        port=args.port,
        headless=args.no_display,
        simulate=args.simulate,
    )

    # Handle signals
    loop = asyncio.get_running_loop()

    def handle_signal():
        asyncio.create_task(agent.stop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    try:
        await agent.start()
    except KeyboardInterrupt:
        pass
    finally:
        await agent.stop()


def run() -> None:
    """Run the agent."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
