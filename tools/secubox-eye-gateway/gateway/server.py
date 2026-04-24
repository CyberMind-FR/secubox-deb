"""
SecuBox Eye Gateway — FastAPI server for development.

Provides both emulation mode and real device connectivity.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .emulator import SecuBoxEmulator
from .remote import EyeRemoteConnection, get_connection, set_connection

# Global emulator instance
_emulator: Optional[SecuBoxEmulator] = None
_mode: str = "emulator"  # "emulator" or "remote"


def set_emulator(emulator: SecuBoxEmulator) -> None:
    """Set the global emulator instance."""
    global _emulator, _mode
    _emulator = emulator
    _mode = "emulator"


def set_remote_mode(host: str = "10.55.0.2", user: str = "pi") -> None:
    """Switch to remote device mode."""
    global _mode
    conn = EyeRemoteConnection(host=host, user=user)
    set_connection(conn)
    _mode = "remote"


def get_emulator() -> SecuBoxEmulator:
    """Get the global emulator instance."""
    if _emulator is None:
        raise HTTPException(status_code=503, detail="Emulator not configured")
    return _emulator


def is_remote_mode() -> bool:
    """Check if running in remote mode."""
    return _mode == "remote"


# Pydantic models for API
class CommandRequest(BaseModel):
    """Request to execute a command."""
    command: str
    timeout: float = 5.0


class ServiceAction(BaseModel):
    """Request to perform service action."""
    service: str
    action: str = "restart"


# FastAPI application
app = FastAPI(
    title="SecuBox Eye Gateway",
    description="Development gateway for SecuBox Eye Remote — Emulation and Remote modes",
    version="2.0.0",
)

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint.

    Returns:
        Health status of the emulated device
    """
    emulator = get_emulator()
    return emulator.get_health()


@app.get("/api/v1/system/metrics")
async def system_metrics() -> Dict[str, Any]:
    """Get system metrics.

    Returns:
        Current system metrics with realistic drift
    """
    emulator = get_emulator()
    return emulator.get_metrics()


@app.get("/api/v1/eye-remote/metrics")
async def eye_remote_metrics() -> Dict[str, Any]:
    """Get metrics formatted for Eye Remote display.

    Returns:
        Metrics in Eye Remote format
    """
    emulator = get_emulator()
    metrics = emulator.get_metrics()

    # Format for Eye Remote display
    return {
        "system": {
            "cpu": metrics["cpu_percent"],
            "memory": metrics["memory_percent"],
            "disk": metrics["disk_percent"],
            "temperature": metrics["temperature"],
            "load": metrics["load_avg"],
        },
        "network": {
            "wifi_signal": metrics["wifi_signal"],
        },
        "alerts": {
            "active": metrics["active_alerts"],
            "critical": max(0, metrics["active_alerts"] - 2),
            "warning": min(metrics["active_alerts"], 2),
        },
        "device": {
            "name": metrics["device_name"],
            "id": metrics["device_id"],
            "uptime": metrics["uptime"],
            "profile": metrics["profile"],
            "emulated": metrics["emulated"],
        },
        "timestamp": metrics["timestamp"],
    }


@app.get("/api/v1/eye-remote/discover")
async def discover() -> Dict[str, Any]:
    """Device discovery endpoint.

    Returns:
        Device discovery information
    """
    emulator = get_emulator()
    return emulator.get_discovery_info()


@app.get("/")
async def root() -> Dict[str, Any]:
    """Root endpoint with basic info."""
    return {
        "name": "SecuBox Eye Gateway",
        "version": "2.0.0",
        "description": "Development gateway for Eye Remote",
        "mode": _mode,
        "docs": "/docs",
        "dashboard": "/dashboard",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Remote Device Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/remote/status")
async def remote_status() -> Dict[str, Any]:
    """Check remote device connection status."""
    conn = get_connection()
    connected = await conn.check_connection()
    return {
        "mode": _mode,
        "host": conn.host,
        "user": conn.user,
        "connected": connected,
    }


@app.post("/api/v1/remote/connect")
async def remote_connect(
    host: str = Query(default="10.55.0.2"),
    user: str = Query(default="pi"),
) -> Dict[str, Any]:
    """Connect to a remote Eye Remote device."""
    conn = EyeRemoteConnection(host=host, user=user)
    connected = await conn.check_connection()

    if connected:
        set_connection(conn)
        global _mode
        _mode = "remote"
        return {
            "status": "connected",
            "host": host,
            "mode": "remote",
        }
    else:
        return {
            "status": "failed",
            "host": host,
            "error": f"Cannot connect to {user}@{host}",
        }


@app.post("/api/v1/remote/command")
async def remote_command(req: CommandRequest) -> Dict[str, Any]:
    """Execute command on remote device."""
    if not is_remote_mode():
        raise HTTPException(
            status_code=400,
            detail="Not in remote mode. Use /api/v1/remote/connect first.",
        )

    conn = get_connection()
    result = await conn.execute(req.command, timeout=req.timeout)
    return result.to_dict()


@app.get("/api/v1/remote/metrics")
async def remote_metrics() -> Dict[str, Any]:
    """Get metrics from remote device."""
    if is_remote_mode():
        conn = get_connection()
        return await conn.get_metrics()
    else:
        # Fallback to emulator
        emulator = get_emulator()
        return emulator.get_metrics()


@app.get("/api/v1/remote/services")
async def remote_services() -> Dict[str, Any]:
    """Get status of SecuBox services on remote device."""
    if not is_remote_mode():
        return {
            "mode": "emulator",
            "services": {
                "secubox-eye-agent": "emulated",
                "secubox-eye-gadget": "emulated",
                "hyperpixel2r-init": "emulated",
                "pigpiod": "emulated",
            },
        }

    conn = get_connection()
    services = await conn.get_services_status()
    return {
        "mode": "remote",
        "host": conn.host,
        "services": services,
    }


@app.post("/api/v1/remote/services/restart")
async def remote_service_restart(req: ServiceAction) -> Dict[str, Any]:
    """Restart a service on remote device."""
    if not is_remote_mode():
        raise HTTPException(
            status_code=400,
            detail="Not in remote mode",
        )

    conn = get_connection()
    result = await conn.restart_service(req.service)
    return {
        "service": req.service,
        "action": "restart",
        "result": result.to_dict(),
    }


@app.get("/api/v1/remote/logs")
async def remote_logs(
    unit: str = Query(default="secubox-eye-agent"),
    lines: int = Query(default=50, le=500),
) -> Dict[str, Any]:
    """Get journal logs from remote device."""
    if not is_remote_mode():
        return {
            "mode": "emulator",
            "logs": "[Emulator mode - no logs available]",
        }

    conn = get_connection()
    logs = await conn.get_journal_logs(unit=unit, lines=lines)
    return {
        "mode": "remote",
        "unit": unit,
        "lines": lines,
        "logs": logs,
    }


@app.get("/api/v1/remote/device")
async def remote_device_info() -> Dict[str, Any]:
    """Get device information from remote."""
    if not is_remote_mode():
        emulator = get_emulator()
        return {
            "mode": "emulator",
            **emulator.get_discovery_info(),
        }

    conn = get_connection()
    info = await conn.get_device_info()
    return {
        "mode": "remote",
        **info,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Test Dashboard (HTML)
# ═══════════════════════════════════════════════════════════════════════════════

from fastapi.responses import HTMLResponse


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the test dashboard HTML."""
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=480, height=480, user-scalable=no">
    <title>SecuBox Eye Gateway — Test Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0a0a0f;
            color: #e8e6d9;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 960px; margin: 0 auto; }
        h1 { color: #00d4ff; margin-bottom: 20px; font-size: 24px; }
        h2 { color: #c9a84c; margin: 20px 0 10px; font-size: 18px; }
        .status-bar {
            display: flex; gap: 20px; padding: 15px;
            background: #1a1a2e; border-radius: 8px; margin-bottom: 20px;
        }
        .status-item { display: flex; align-items: center; gap: 8px; }
        .status-dot { width: 12px; height: 12px; border-radius: 50%; }
        .status-dot.ok { background: #00ff41; }
        .status-dot.error { background: #e63946; }
        .status-dot.warn { background: #c9a84c; }
        .card {
            background: #1a1a2e; border-radius: 8px; padding: 15px;
            margin-bottom: 15px;
        }
        .metrics-grid {
            display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;
        }
        .metric {
            background: #252538; border-radius: 6px; padding: 15px;
            text-align: center;
        }
        .metric-value { font-size: 32px; font-weight: bold; color: #00d4ff; }
        .metric-label { font-size: 12px; color: #6b6b7a; margin-top: 5px; }
        .btn {
            background: #3D35A0; color: white; border: none; padding: 10px 20px;
            border-radius: 4px; cursor: pointer; font-family: inherit; margin: 5px;
        }
        .btn:hover { background: #5046c0; }
        .btn.danger { background: #e63946; }
        .btn.success { background: #0A5840; }
        .terminal {
            background: #000; color: #00ff41; padding: 15px;
            font-family: monospace; font-size: 12px;
            height: 200px; overflow-y: auto; border-radius: 4px;
            white-space: pre-wrap; word-break: break-all;
        }
        input[type="text"] {
            background: #252538; border: 1px solid #3a3a4a; color: #e8e6d9;
            padding: 10px; border-radius: 4px; font-family: inherit; width: 100%;
        }
        .services { display: flex; flex-wrap: wrap; gap: 10px; }
        .service {
            display: flex; align-items: center; gap: 8px;
            background: #252538; padding: 8px 12px; border-radius: 4px;
        }
        .service.active .status-dot { background: #00ff41; }
        .service.inactive .status-dot { background: #e63946; }
        .service.unknown .status-dot { background: #6b6b7a; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ SecuBox Eye Gateway</h1>

        <div class="status-bar">
            <div class="status-item">
                <span class="status-dot" id="mode-dot"></span>
                <span>Mode: <strong id="mode-text">-</strong></span>
            </div>
            <div class="status-item">
                <span class="status-dot" id="conn-dot"></span>
                <span>Connection: <strong id="conn-text">-</strong></span>
            </div>
            <div class="status-item">
                <span>Host: <strong id="host-text">-</strong></span>
            </div>
        </div>

        <div class="card">
            <h2>📡 Connect to Device</h2>
            <div style="display: flex; gap: 10px; margin-top: 10px;">
                <input type="text" id="host-input" placeholder="10.55.0.2" value="10.55.0.2">
                <button class="btn success" onclick="connectDevice()">Connect</button>
                <button class="btn" onclick="useEmulator()">Emulator Mode</button>
            </div>
        </div>

        <h2>📊 System Metrics</h2>
        <div class="metrics-grid">
            <div class="metric">
                <div class="metric-value" id="cpu">-</div>
                <div class="metric-label">CPU %</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="memory">-</div>
                <div class="metric-label">Memory %</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="disk">-</div>
                <div class="metric-label">Disk %</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="temp">-</div>
                <div class="metric-label">Temp °C</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="load">-</div>
                <div class="metric-label">Load Avg</div>
            </div>
            <div class="metric">
                <div class="metric-value" id="uptime">-</div>
                <div class="metric-label">Uptime</div>
            </div>
        </div>

        <div class="card">
            <h2>🔧 Services</h2>
            <div class="services" id="services">
                <div class="service unknown"><span class="status-dot"></span>Loading...</div>
            </div>
            <div style="margin-top: 15px;">
                <button class="btn" onclick="restartAgent()">Restart Agent</button>
                <button class="btn" onclick="restartGadget()">Restart Gadget</button>
                <button class="btn" onclick="refreshServices()">Refresh</button>
            </div>
        </div>

        <div class="card">
            <h2>💻 Remote Command</h2>
            <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                <input type="text" id="cmd-input" placeholder="Enter command..." value="uname -a">
                <button class="btn" onclick="runCommand()">Run</button>
            </div>
            <div class="terminal" id="terminal">Ready...</div>
        </div>

        <div class="card">
            <h2>📜 Logs</h2>
            <div style="margin-bottom: 10px;">
                <button class="btn" onclick="getLogs('secubox-eye-agent')">Agent Logs</button>
                <button class="btn" onclick="getLogs('secubox-eye-gadget')">Gadget Logs</button>
                <button class="btn" onclick="getLogs('hyperpixel2r-init')">Display Logs</button>
            </div>
            <div class="terminal" id="logs">Select a log source...</div>
        </div>
    </div>

    <script>
        const API = '';
        let refreshInterval;

        async function fetchJson(url, opts = {}) {
            const res = await fetch(API + url, opts);
            return res.json();
        }

        async function refreshStatus() {
            try {
                const status = await fetchJson('/api/v1/remote/status');
                document.getElementById('mode-text').textContent = status.mode;
                document.getElementById('conn-text').textContent = status.connected ? 'Connected' : 'Disconnected';
                document.getElementById('host-text').textContent = status.host;
                document.getElementById('mode-dot').className = 'status-dot ' + (status.mode === 'remote' ? 'ok' : 'warn');
                document.getElementById('conn-dot').className = 'status-dot ' + (status.connected ? 'ok' : 'error');
            } catch (e) {
                console.error('Status error:', e);
            }
        }

        async function refreshMetrics() {
            try {
                const m = await fetchJson('/api/v1/remote/metrics');
                document.getElementById('cpu').textContent = (m.cpu_percent || 0).toFixed(1);
                document.getElementById('memory').textContent = (m.memory_percent || 0).toFixed(1);
                document.getElementById('disk').textContent = (m.disk_percent || 0).toFixed(1);
                document.getElementById('temp').textContent = (m.temperature || 0).toFixed(1);
                document.getElementById('load').textContent = (m.load_avg || 0).toFixed(2);
                if (m.uptime_seconds) {
                    const h = Math.floor(m.uptime_seconds / 3600);
                    const min = Math.floor((m.uptime_seconds % 3600) / 60);
                    document.getElementById('uptime').textContent = h + 'h' + min + 'm';
                }
            } catch (e) {
                console.error('Metrics error:', e);
            }
        }

        async function refreshServices() {
            try {
                const data = await fetchJson('/api/v1/remote/services');
                const container = document.getElementById('services');
                container.innerHTML = '';
                for (const [name, status] of Object.entries(data.services)) {
                    const cls = status === 'active' ? 'active' : (status === 'inactive' ? 'inactive' : 'unknown');
                    container.innerHTML += `<div class="service ${cls}"><span class="status-dot"></span>${name}: ${status}</div>`;
                }
            } catch (e) {
                console.error('Services error:', e);
            }
        }

        async function connectDevice() {
            const host = document.getElementById('host-input').value || '10.55.0.2';
            const term = document.getElementById('terminal');
            term.textContent = 'Connecting to ' + host + '...';
            try {
                const res = await fetchJson('/api/v1/remote/connect?host=' + host, { method: 'POST' });
                term.textContent = JSON.stringify(res, null, 2);
                if (res.status === 'connected') {
                    refreshAll();
                }
            } catch (e) {
                term.textContent = 'Error: ' + e.message;
            }
        }

        function useEmulator() {
            document.getElementById('mode-text').textContent = 'emulator';
            document.getElementById('mode-dot').className = 'status-dot warn';
            document.getElementById('terminal').textContent = 'Switched to emulator mode';
            refreshAll();
        }

        async function runCommand() {
            const cmd = document.getElementById('cmd-input').value;
            const term = document.getElementById('terminal');
            term.textContent = '$ ' + cmd + '\\n\\nExecuting...';
            try {
                const res = await fetchJson('/api/v1/remote/command', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command: cmd }),
                });
                term.textContent = '$ ' + cmd + '\\n\\n' + (res.stdout || res.stderr || 'No output');
                if (res.return_code !== 0) {
                    term.textContent += '\\n\\n[Exit code: ' + res.return_code + ']';
                }
            } catch (e) {
                term.textContent = 'Error: ' + e.message;
            }
        }

        async function getLogs(unit) {
            const logsDiv = document.getElementById('logs');
            logsDiv.textContent = 'Loading ' + unit + ' logs...';
            try {
                const res = await fetchJson('/api/v1/remote/logs?unit=' + unit + '&lines=100');
                logsDiv.textContent = res.logs || 'No logs available';
            } catch (e) {
                logsDiv.textContent = 'Error: ' + e.message;
            }
        }

        async function restartAgent() {
            await restartService('secubox-eye-agent');
        }

        async function restartGadget() {
            await restartService('secubox-eye-gadget');
        }

        async function restartService(name) {
            const term = document.getElementById('terminal');
            term.textContent = 'Restarting ' + name + '...';
            try {
                const res = await fetchJson('/api/v1/remote/services/restart', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ service: name }),
                });
                term.textContent = JSON.stringify(res, null, 2);
                setTimeout(refreshServices, 2000);
            } catch (e) {
                term.textContent = 'Error: ' + e.message;
            }
        }

        function refreshAll() {
            refreshStatus();
            refreshMetrics();
            refreshServices();
        }

        // Initial load
        refreshAll();

        // Auto-refresh every 5 seconds
        refreshInterval = setInterval(() => {
            refreshStatus();
            refreshMetrics();
        }, 5000);

        // Handle Enter key in command input
        document.getElementById('cmd-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') runCommand();
        });
    </script>
</body>
</html>
"""
    return HTMLResponse(content=html, status_code=200)
