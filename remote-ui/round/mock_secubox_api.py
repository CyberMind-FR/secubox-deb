#!/usr/bin/env python3
"""
SecuBox Eye Remote — Mock SecuBox API
Emulates SecuBox API for Eye Remote testing without real hardware.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>

Usage:
    python3 mock_secubox_api.py [--host 10.55.0.1] [--port 8000]
"""
import argparse
import random
import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

START_TIME = time.time()

# Simulated metrics with realistic drift
class MetricsSimulator:
    def __init__(self):
        self.cpu = 25.0
        self.mem = 45.0
        self.disk = 32.0
        self.load = 0.5
        self.temp = 42.0
        self.wifi = -55

    def update(self):
        self.cpu = max(5, min(95, self.cpu + random.uniform(-5, 5)))
        self.mem = max(20, min(85, self.mem + random.uniform(-2, 2)))
        self.disk = max(10, min(90, self.disk + random.uniform(-0.1, 0.1)))
        self.load = max(0.1, min(4.0, self.load + random.uniform(-0.2, 0.2)))
        self.temp = max(35, min(70, self.temp + random.uniform(-1, 1)))
        self.wifi = max(-80, min(-30, self.wifi + random.randint(-3, 3)))

        return {
            "cpu_percent": round(self.cpu, 1),
            "mem_percent": round(self.mem, 1),
            "disk_percent": round(self.disk, 1),
            "load_avg_1": round(self.load, 2),
            "cpu_temp": round(self.temp, 1),
            "wifi_rssi": self.wifi,
            "uptime_seconds": int(time.time() - START_TIME),
            "hostname": "secubox-mock",
            "secubox_version": "2.0.0-emulator",
            "modules_active": ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]
        }


simulator = MetricsSimulator()


class SecuBoxAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mock SecuBox API."""

    def log_message(self, format, *args):
        print(f"[API] {args[0]}")

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/v1/health':
            self.send_json({
                "status": "ok",
                "version": "2.0.0-emulator",
                "mode": "mock"
            })

        elif self.path == '/api/v1/system/metrics':
            self.send_json(simulator.update())

        elif self.path == '/api/v1/system/modules':
            self.send_json({
                "modules": [
                    {"name": "AUTH", "status": "active", "version": "1.0.0"},
                    {"name": "WALL", "status": "active", "version": "1.0.0"},
                    {"name": "BOOT", "status": "active", "version": "1.0.0"},
                    {"name": "MIND", "status": "active", "version": "1.0.0"},
                    {"name": "ROOT", "status": "active", "version": "1.0.0"},
                    {"name": "MESH", "status": "active", "version": "1.0.0"},
                ]
            })

        elif self.path == '/api/v1/system/alerts':
            self.send_json({
                "global_level": "nominal",
                "items": []
            })

        else:
            self.send_json({"error": "Not found"}, 404)


def run_server(host='10.55.0.1', port=8000):
    """Run the mock API server."""
    server = HTTPServer((host, port), SecuBoxAPIHandler)
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║       SecuBox Mock API Server — Eye Remote Emulator          ║
╠══════════════════════════════════════════════════════════════╣
║  Listening: http://{host}:{port}                          ║
║                                                              ║
║  Endpoints:                                                  ║
║    GET /api/v1/health         → Health check                 ║
║    GET /api/v1/system/metrics → System metrics (simulated)   ║
║    GET /api/v1/system/modules → Module status                ║
║    GET /api/v1/system/alerts  → Alerts                       ║
║                                                              ║
║  Press Ctrl+C to stop                                        ║
╚══════════════════════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mock SecuBox API for Eye Remote testing')
    parser.add_argument('--host', default='10.55.0.1', help='Host to bind (default: 10.55.0.1)')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind (default: 8000)')
    args = parser.parse_args()

    run_server(args.host, args.port)
