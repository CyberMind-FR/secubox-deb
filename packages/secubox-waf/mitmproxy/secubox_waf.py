# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma
"""SecuBox WAF Addon for mitmproxy - Reverse Proxy with Dynamic Routing

This addon routes requests based on Host header to backend services
defined in haproxy-routes.json. All inspected traffic is tagged with
the X-SecuBox-WAF header.
"""
import json
import logging
from pathlib import Path
from mitmproxy import http, ctx

ROUTES_FILE = Path("/srv/mitmproxy/haproxy-routes.json")
LOG_DIR = Path("/var/log/mitmproxy")


class SecuBoxWAF:
    """SecuBox Web Application Firewall addon for mitmproxy."""

    def __init__(self):
        self.routes = {}
        self.load_routes()

    def load_routes(self):
        """Load routing configuration from JSON file."""
        if ROUTES_FILE.exists():
            try:
                self.routes = json.loads(ROUTES_FILE.read_text())
                ctx.log.info(f"SecuBox WAF: Loaded {len(self.routes)} routes")
            except Exception as e:
                ctx.log.error(f"SecuBox WAF: Failed to load routes: {e}")
        else:
            ctx.log.warn(f"SecuBox WAF: Routes file not found: {ROUTES_FILE}")

    def request(self, flow: http.HTTPFlow):
        """Process incoming request and route to appropriate backend."""
        # Get host from Host header or request
        host = flow.request.host_header or flow.request.pretty_host

        # Log request
        log_line = f"{flow.request.method} {host}{flow.request.path}"
        ctx.log.info(f"WAF: {log_line}")

        # Route based on Host header
        if host in self.routes:
            backend_ip, backend_port = self.routes[host]
            flow.request.host = backend_ip
            flow.request.port = backend_port
            ctx.log.info(f"WAF: Routing {host} -> {backend_ip}:{backend_port}")
        else:
            ctx.log.warn(f"WAF: No route for {host}")

    def response(self, flow: http.HTTPFlow):
        """Process response and add WAF header."""
        flow.response.headers["X-SecuBox-WAF"] = "inspected"


addons = [SecuBoxWAF()]
