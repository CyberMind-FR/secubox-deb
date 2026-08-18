#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote — Pi Zero Metrics API
Minimal HTTP server providing system metrics for MOCHAbin dashboard.

Run: python3 pizero-metrics-api.py
Listens on: 0.0.0.0:8000

CyberMind — https://cybermind.fr
"""
import json
import os
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

def get_cpu_temp():
    """Read CPU temperature from thermal zone."""
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return float(f.read().strip()) / 1000.0
    except Exception:
        return 0.0

def get_uptime():
    """Get system uptime in seconds."""
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return 0

def get_load_avg():
    """Get load averages."""
    try:
        return os.getloadavg()
    except Exception:
        return (0.0, 0.0, 0.0)

def get_memory_percent():
    """Get memory usage percentage."""
    try:
        with open("/proc/meminfo") as f:
            info = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1])
            total = info.get("MemTotal", 1)
            available = info.get("MemAvailable", info.get("MemFree", 0))
            return ((total - available) / total) * 100
    except Exception:
        return 0.0

def get_disk_percent():
    """Get disk usage percentage."""
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total > 0:
            return ((total - free) / total) * 100
        return 0.0
    except Exception:
        return 0.0

def get_metrics():
    """Collect all system metrics."""
    load_1, load_5, load_15 = get_load_avg()
    cpu_count = os.cpu_count() or 1
    cpu_percent = min(100.0, (load_1 / cpu_count) * 100)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hostname": socket.gethostname(),
        "cpu_percent": round(cpu_percent, 1),
        "cpu_temp": round(get_cpu_temp(), 1),
        "mem_percent": round(get_memory_percent(), 1),
        "disk_percent": round(get_disk_percent(), 1),
        "uptime_seconds": get_uptime(),
        "load_1m": round(load_1, 2),
        "load_5m": round(load_5, 2),
        "load_15m": round(load_15, 2),
    }


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for metrics API."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def send_json(self, data, status=200):
        """Send JSON response."""
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/api/v1/status" or self.path == "/metrics":
            self.send_json(get_metrics())
        elif self.path == "/health":
            self.send_json({"status": "ok", "service": "pizero-metrics"})
        else:
            self.send_json({"error": "Not found"}, 404)


def main():
    """Start the metrics server."""
    host = "0.0.0.0"
    port = 8000
    server = HTTPServer((host, port), MetricsHandler)
    print(f"Pi Zero Metrics API running on http://{host}:{port}")
    print("Endpoints:")
    print("  GET /api/v1/status  - System metrics")
    print("  GET /metrics        - System metrics (alias)")
    print("  GET /health         - Health check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
