"""
SecuBox Eye Remote — Web Server
FastAPI application factory and WebServer class for Eye Remote control API.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

if TYPE_CHECKING:
    from agent.mode_manager import ModeManager
    from agent.failover import FailoverMonitor
    from agent.config import Config

log = logging.getLogger(__name__)

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"


def _default_control_html() -> str:
    """
    Return default HTML control page.

    Returns:
        HTML content for the control interface
    """
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Eye Remote Control</title>
    <style>
        :root {
            --cosmos-black: #0a0a0f;
            --gold-hermetic: #c9a84c;
            --cinnabar: #e63946;
            --matrix-green: #00ff41;
            --void-purple: #6e40c9;
            --cyber-cyan: #00d4ff;
            --text-primary: #e8e6d9;
            --text-muted: #6b6b7a;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            background-color: var(--cosmos-black);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            min-height: 100vh;
            padding: 20px;
        }
        h1 {
            color: var(--gold-hermetic);
            font-family: 'Cinzel', serif;
            text-align: center;
            margin-bottom: 30px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .section {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--void-purple);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .section h2 {
            color: var(--cyber-cyan);
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        .mode-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        button {
            background: var(--void-purple);
            color: var(--text-primary);
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-family: inherit;
            transition: all 0.2s;
        }
        button:hover {
            background: var(--cyber-cyan);
            color: var(--cosmos-black);
        }
        button.active {
            background: var(--matrix-green);
            color: var(--cosmos-black);
        }
        .status {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 15px;
        }
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--matrix-green);
        }
        .status-dot.disconnected {
            background: var(--cinnabar);
        }
        #current-mode {
            color: var(--gold-hermetic);
            font-weight: bold;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .info-item {
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            border-radius: 5px;
        }
        .info-item label {
            color: var(--text-muted);
            font-size: 0.9em;
        }
        .info-item .value {
            color: var(--cyber-cyan);
            font-size: 1.2em;
            margin-top: 5px;
        }
        footer {
            text-align: center;
            margin-top: 40px;
            color: var(--text-muted);
            font-size: 0.8em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Eye Remote Control</h1>

        <div class="section">
            <h2>Mode Control</h2>
            <div class="mode-buttons">
                <button onclick="setMode('dashboard')">Dashboard</button>
                <button onclick="setMode('local')">Local</button>
                <button onclick="setMode('flash')">Flash</button>
                <button onclick="setMode('gateway')">Gateway</button>
            </div>
            <div class="status">
                <span class="status-dot" id="status-dot"></span>
                <span>Current mode: <span id="current-mode">loading...</span></span>
            </div>
        </div>

        <div class="section">
            <h2>System Info</h2>
            <div class="info-grid">
                <div class="info-item">
                    <label>Hostname</label>
                    <div class="value" id="hostname">-</div>
                </div>
                <div class="info-item">
                    <label>Uptime</label>
                    <div class="value" id="uptime">-</div>
                </div>
                <div class="info-item">
                    <label>WiFi Status</label>
                    <div class="value" id="wifi-status">-</div>
                </div>
                <div class="info-item">
                    <label>Bluetooth</label>
                    <div class="value" id="bt-status">-</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Display</h2>
            <div class="info-grid">
                <div class="info-item">
                    <label>Brightness</label>
                    <input type="range" min="0" max="100" value="80" id="brightness"
                           onchange="setBrightness(this.value)">
                </div>
            </div>
        </div>

        <footer>
            <p>SecuBox Eye Remote &middot; CyberMind</p>
        </footer>
    </div>

    <script>
        const API_BASE = '/api';

        async function fetchMode() {
            try {
                const resp = await fetch(`${API_BASE}/mode`);
                if (resp.ok) {
                    const data = await resp.json();
                    document.getElementById('current-mode').textContent = data.mode;
                    document.getElementById('status-dot').classList.remove('disconnected');
                    updateModeButtons(data.mode);
                } else {
                    document.getElementById('current-mode').textContent = 'unavailable';
                    document.getElementById('status-dot').classList.add('disconnected');
                }
            } catch (e) {
                document.getElementById('current-mode').textContent = 'error';
                document.getElementById('status-dot').classList.add('disconnected');
            }
        }

        async function setMode(mode) {
            try {
                const resp = await fetch(`${API_BASE}/mode`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({mode: mode})
                });
                if (resp.ok) {
                    const data = await resp.json();
                    document.getElementById('current-mode').textContent = data.mode;
                    updateModeButtons(data.mode);
                }
            } catch (e) {
                console.error('Failed to set mode:', e);
            }
        }

        function updateModeButtons(currentMode) {
            document.querySelectorAll('.mode-buttons button').forEach(btn => {
                btn.classList.remove('active');
                if (btn.textContent.toLowerCase() === currentMode) {
                    btn.classList.add('active');
                }
            });
        }

        async function fetchSystemInfo() {
            try {
                const resp = await fetch(`${API_BASE}/system/info`);
                if (resp.ok) {
                    const data = await resp.json();
                    document.getElementById('hostname').textContent = data.hostname || '-';
                    document.getElementById('uptime').textContent = data.uptime || '-';
                }
            } catch (e) {
                console.error('Failed to fetch system info:', e);
            }
        }

        async function fetchWifiStatus() {
            try {
                const resp = await fetch(`${API_BASE}/wifi/status`);
                if (resp.ok) {
                    const data = await resp.json();
                    document.getElementById('wifi-status').textContent =
                        data.connected ? 'Connected' : 'Disconnected';
                }
            } catch (e) {
                document.getElementById('wifi-status').textContent = '-';
            }
        }

        async function fetchBluetoothStatus() {
            try {
                const resp = await fetch(`${API_BASE}/bluetooth/status`);
                if (resp.ok) {
                    const data = await resp.json();
                    document.getElementById('bt-status').textContent =
                        data.enabled ? 'Enabled' : 'Disabled';
                }
            } catch (e) {
                document.getElementById('bt-status').textContent = '-';
            }
        }

        async function setBrightness(value) {
            try {
                await fetch(`${API_BASE}/display/brightness`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({value: parseInt(value)})
                });
            } catch (e) {
                console.error('Failed to set brightness:', e);
            }
        }

        // Initial load
        fetchMode();
        fetchSystemInfo();
        fetchWifiStatus();
        fetchBluetoothStatus();

        // Refresh mode every 5 seconds
        setInterval(fetchMode, 5000);
    </script>
</body>
</html>"""


def create_app(
    mode_manager: Optional["ModeManager"] = None,
    failover_monitor: Optional["FailoverMonitor"] = None,
    config: Optional["Config"] = None,
) -> FastAPI:
    """
    Create FastAPI application for Eye Remote web control.

    Args:
        mode_manager: ModeManager instance for mode control
        failover_monitor: FailoverMonitor instance for connection status
        config: Config instance with settings

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="Eye Remote Web API",
        description="Web control API for SecuBox Eye Remote device",
        version="1.0.0",
    )

    # Store dependencies in app state
    app.state.mode_manager = mode_manager
    app.state.failover_monitor = failover_monitor
    app.state.config = config

    # Import and include routers
    from agent.web.routes import mode, wifi, bluetooth, display, devices, system, secubox

    app.include_router(mode.router, prefix="/api", tags=["mode"])
    app.include_router(wifi.router, prefix="/api/wifi", tags=["wifi"])
    app.include_router(bluetooth.router, prefix="/api/bluetooth", tags=["bluetooth"])
    app.include_router(display.router, prefix="/api/display", tags=["display"])
    app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
    app.include_router(system.router, prefix="/api/system", tags=["system"])
    app.include_router(secubox.router, prefix="/api/secubox", tags=["secubox"])

    # Health endpoint
    @app.get("/api/health", tags=["health"])
    async def health_check():
        """Health check endpoint."""
        return {"status": "ok", "service": "eye-remote-web"}

    # Control page
    @app.get("/control", response_class=HTMLResponse, tags=["ui"])
    async def control_page():
        """Serve control HTML page."""
        # Check for custom control.html in static directory
        control_html_path = STATIC_DIR / "control.html"
        if control_html_path.exists():
            return control_html_path.read_text()
        return _default_control_html()

    # Mount static files if directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    log.info("Eye Remote Web API initialized")
    return app


class WebServer:
    """
    Web server wrapper for Eye Remote control API.

    Manages uvicorn server lifecycle for the FastAPI application.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        mode_manager: Optional["ModeManager"] = None,
        failover_monitor: Optional["FailoverMonitor"] = None,
        config: Optional["Config"] = None,
    ):
        """
        Initialize WebServer.

        Args:
            host: Bind address (default: 0.0.0.0)
            port: Bind port (default: 8080)
            mode_manager: ModeManager instance
            failover_monitor: FailoverMonitor instance
            config: Config instance
        """
        self.host = host
        self.port = port
        self.app = create_app(
            mode_manager=mode_manager,
            failover_monitor=failover_monitor,
            config=config,
        )
        self._server = None
        self._serve_task = None

    async def start(self) -> None:
        """Start the web server."""
        import uvicorn

        config = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info",
        )
        self._server = uvicorn.Server(config)

        # Run server in background task
        self._serve_task = asyncio.create_task(self._server.serve())
        log.info(f"Web server started on http://{self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the web server."""
        if self._server:
            self._server.should_exit = True
            if self._serve_task:
                try:
                    await asyncio.wait_for(self._serve_task, timeout=5.0)
                except asyncio.TimeoutError:
                    self._serve_task.cancel()
            log.info("Web server stopped")
