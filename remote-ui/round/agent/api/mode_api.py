#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote - Mode Control Web API

Simple HTTP API for manual gadget mode switching.
Safer than auto-switching - user-triggered only.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import json
import os
import subprocess
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, Any
import urllib.parse

# Gadget paths
GADGET_PATH = Path("/sys/kernel/config/usb_gadget/secubox")
GADGET_SCRIPT = Path("/etc/secubox/eye-remote/gadget-setup.sh")

# Available modes
MODES = {
    "composite": "up",      # ECM + ACM + Storage (full)
    "network": "network",   # ECM + ACM only
    "storage": "storage",   # Storage only (U-Boot)
    "silent": "silent",     # Storage + ACM (silent fallback)
    "hid": "hid",          # HID + ACM
}


def get_current_mode() -> Dict[str, Any]:
    """Get current gadget mode and status."""
    result = {
        "mode": "unknown",
        "functions": [],
        "udc": None,
        "udc_state": "unknown",
    }

    # Check UDC
    udc_file = GADGET_PATH / "UDC"
    if udc_file.exists():
        try:
            result["udc"] = udc_file.read_text().strip() or None
        except:
            pass

    # Check functions
    configs_path = GADGET_PATH / "configs" / "c.1"
    if configs_path.exists():
        for item in configs_path.iterdir():
            if item.is_symlink():
                name = item.name
                if "ecm" in name:
                    result["functions"].append("ecm")
                elif "acm" in name:
                    result["functions"].append("acm")
                elif "mass_storage" in name:
                    result["functions"].append("storage")
                elif "hid" in name:
                    result["functions"].append("hid")
                elif "rndis" in name:
                    result["functions"].append("rndis")

    # Determine mode from functions
    funcs = set(result["functions"])
    if funcs == {"ecm", "acm", "storage"} or funcs == {"ecm", "acm", "storage", "rndis"}:
        result["mode"] = "composite"
    elif funcs == {"ecm", "acm"} or funcs == {"ecm", "acm", "rndis"}:
        result["mode"] = "network"
    elif funcs == {"storage", "acm"}:
        result["mode"] = "silent"
    elif funcs == {"storage"}:
        result["mode"] = "storage"
    elif funcs == {"hid", "acm"}:
        result["mode"] = "hid"
    elif not funcs:
        result["mode"] = "none"

    # Check UDC state
    if result["udc"]:
        state_file = Path(f"/sys/class/udc/{result['udc']}/state")
        if state_file.exists():
            try:
                result["udc_state"] = state_file.read_text().strip()
            except:
                pass

    return result


def get_system_metrics() -> Dict[str, Any]:
    """Get Pi Zero system metrics."""
    metrics = {
        "cpu_percent": 0,
        "memory_percent": 0,
        "disk_percent": 0,
        "cpu_temp": 0,
        "load_avg": [0, 0, 0],
        "uptime_seconds": 0,
        "hostname": "unknown",
    }

    try:
        # CPU usage from /proc/stat (simple approximation)
        with open("/proc/stat") as f:
            line = f.readline()
            parts = line.split()[1:8]
            total = sum(int(p) for p in parts)
            idle = int(parts[3])
            metrics["cpu_percent"] = round(100 * (1 - idle / total), 1) if total > 0 else 0
    except:
        pass

    try:
        # Memory from /proc/meminfo
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    mem[parts[0].rstrip(":")] = int(parts[1])
            total = mem.get("MemTotal", 1)
            avail = mem.get("MemAvailable", mem.get("MemFree", 0))
            metrics["memory_percent"] = round(100 * (1 - avail / total), 1)
    except:
        pass

    try:
        # Disk usage
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        metrics["disk_percent"] = round(100 * (1 - free / total), 1) if total > 0 else 0
    except:
        pass

    try:
        # CPU temperature
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            metrics["cpu_temp"] = round(int(f.read().strip()) / 1000, 1)
    except:
        pass

    try:
        # Load average
        metrics["load_avg"] = list(os.getloadavg())
    except:
        pass

    try:
        # Uptime
        with open("/proc/uptime") as f:
            metrics["uptime_seconds"] = int(float(f.read().split()[0]))
    except:
        pass

    try:
        # Hostname
        with open("/etc/hostname") as f:
            metrics["hostname"] = f.read().strip()
    except:
        pass

    return metrics


def switch_mode(mode: str) -> Dict[str, Any]:
    """Switch gadget mode using the setup script."""
    if mode not in MODES:
        return {"success": False, "error": f"Unknown mode: {mode}"}

    script_arg = MODES[mode]

    if not GADGET_SCRIPT.exists():
        return {"success": False, "error": "Gadget script not found"}

    start_time = time.time()

    try:
        result = subprocess.run(
            ["sudo", str(GADGET_SCRIPT), script_arg],
            capture_output=True,
            text=True,
            timeout=15
        )

        duration = (time.time() - start_time) * 1000

        if result.returncode == 0:
            return {
                "success": True,
                "mode": mode,
                "duration_ms": round(duration, 1),
                "output": result.stdout.strip()
            }
        else:
            return {
                "success": False,
                "error": result.stderr.strip() or "Script failed",
                "returncode": result.returncode
            }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout (15s)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


class ModeAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mode API."""

    def _send_json(self, data: Dict, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def _send_html(self, html: str, status: int = 200):
        """Send HTML response."""
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_GET(self):
        """Handle GET requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            # Serve control panel
            self._serve_control_panel()
        elif path == "/api/status":
            # Get current status
            status = get_current_mode()
            self._send_json(status)
        elif path == "/api/modes":
            # List available modes
            self._send_json({"modes": list(MODES.keys())})
        elif path == "/health":
            # Health check for dashboard
            self._send_json({"status": "ok"})
        elif path == "/metrics":
            # System metrics for dashboard
            metrics = get_system_metrics()
            metrics["gadget"] = get_current_mode()
            self._send_json(metrics)
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        """Handle POST requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/switch/"):
            mode = path.split("/")[-1]
            result = switch_mode(mode)
            status_code = 200 if result.get("success") else 400
            self._send_json(result, status_code)
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _serve_control_panel(self):
        """Serve the mode control panel HTML."""
        status = get_current_mode()

        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Eye Remote - Mode Control</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{
            font-family: 'JetBrains Mono', monospace;
            background: #0a0a0f;
            color: #e8e6d9;
            margin: 0;
            padding: 20px;
        }}
        h1 {{
            color: #c9a84c;
            text-align: center;
        }}
        .status {{
            background: #1a1a2e;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .mode {{
            font-size: 24px;
            color: #00ff41;
        }}
        .functions {{
            color: #00d4ff;
            margin: 10px 0;
        }}
        .buttons {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
            margin: 20px 0;
        }}
        button {{
            background: #1a1a2e;
            color: #e8e6d9;
            border: 2px solid #c9a84c;
            padding: 15px 25px;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
            min-width: 120px;
        }}
        button:hover {{
            background: #c9a84c;
            color: #0a0a0f;
        }}
        button:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        button.active {{
            background: #00ff41;
            color: #0a0a0f;
            border-color: #00ff41;
        }}
        .result {{
            background: #1a1a2e;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            display: none;
        }}
        .result.success {{
            border-left: 4px solid #00ff41;
        }}
        .result.error {{
            border-left: 4px solid #e63946;
        }}
        .warning {{
            background: #3d2010;
            border: 1px solid #c9a84c;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <h1>SecuBox Eye Remote</h1>
    <h2 style="text-align:center; color:#6b6b7a">Mode Control</h2>

    <div class="status">
        <div>Current Mode: <span class="mode" id="current-mode">{status['mode'].upper()}</span></div>
        <div class="functions">Functions: <span id="functions">{', '.join(status['functions']) or 'none'}</span></div>
        <div>UDC: <span id="udc">{status['udc'] or 'none'}</span> ({status['udc_state']})</div>
    </div>

    <div class="warning">
        ⚠️ Mode switching may cause brief USB disconnection. Network will recover automatically.
    </div>

    <div class="buttons">
        <button onclick="switchMode('composite')" id="btn-composite">COMPOSITE</button>
        <button onclick="switchMode('network')" id="btn-network">NETWORK</button>
        <button onclick="switchMode('storage')" id="btn-storage">STORAGE</button>
        <button onclick="switchMode('silent')" id="btn-silent">SILENT</button>
        <button onclick="switchMode('hid')" id="btn-hid">HID</button>
    </div>

    <div class="result" id="result"></div>

    <script>
        function updateButtons() {{
            const mode = document.getElementById('current-mode').textContent.toLowerCase();
            document.querySelectorAll('.buttons button').forEach(btn => {{
                btn.classList.remove('active');
                if (btn.id === 'btn-' + mode) {{
                    btn.classList.add('active');
                }}
            }});
        }}

        async function switchMode(mode) {{
            const resultDiv = document.getElementById('result');
            resultDiv.style.display = 'block';
            resultDiv.className = 'result';
            resultDiv.textContent = 'Switching to ' + mode.toUpperCase() + '...';

            // Disable all buttons
            document.querySelectorAll('.buttons button').forEach(btn => btn.disabled = true);

            try {{
                const resp = await fetch('/api/switch/' + mode, {{ method: 'POST' }});
                const data = await resp.json();

                if (data.success) {{
                    resultDiv.className = 'result success';
                    resultDiv.textContent = '✓ Switched to ' + mode.toUpperCase() + ' (' + data.duration_ms + 'ms)';
                    document.getElementById('current-mode').textContent = mode.toUpperCase();
                    updateButtons();

                    // Refresh status after 2s
                    setTimeout(refreshStatus, 2000);
                }} else {{
                    resultDiv.className = 'result error';
                    resultDiv.textContent = '✗ Error: ' + data.error;
                }}
            }} catch (e) {{
                resultDiv.className = 'result error';
                resultDiv.textContent = '✗ Connection lost (mode switch may have succeeded)';
                // Try to refresh after reconnection
                setTimeout(refreshStatus, 5000);
            }}

            // Re-enable buttons
            document.querySelectorAll('.buttons button').forEach(btn => btn.disabled = false);
        }}

        async function refreshStatus() {{
            try {{
                const resp = await fetch('/api/status');
                const data = await resp.json();
                document.getElementById('current-mode').textContent = data.mode.toUpperCase();
                document.getElementById('functions').textContent = data.functions.join(', ') || 'none';
                document.getElementById('udc').textContent = data.udc || 'none';
                updateButtons();
            }} catch (e) {{
                console.log('Status refresh failed');
            }}
        }}

        // Initial button state
        updateButtons();

        // Auto-refresh every 10s
        setInterval(refreshStatus, 10000);
    </script>
</body>
</html>'''
        self._send_html(html)

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def main():
    """Run the mode control API server."""
    port = 8081  # 8080 used by CrowdSec
    server = HTTPServer(('0.0.0.0', port), ModeAPIHandler)
    print(f"Mode Control API running on http://0.0.0.0:{port}")
    print("Endpoints:")
    print("  GET  /           - Control panel")
    print("  GET  /api/status - Current mode")
    print("  POST /api/switch/<mode> - Switch mode")
    server.serve_forever()


if __name__ == "__main__":
    main()
