# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote - Web Server
FastAPI-based HTTP API for remote control and monitoring.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import asyncio
import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


class WebServer:
    """
    HTTP API server for Eye Remote.
    Provides endpoints for metrics, configuration, and control.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        mode_manager: Any = None,
        failover_monitor: Any = None,
        config: Any = None,
        wifi_manager: Any = None,
        bluetooth_manager: Any = None,
        display_controller: Any = None,
    ):
        self.host = host
        self.port = port
        self.mode_manager = mode_manager
        self.failover_monitor = failover_monitor
        self.config = config
        self.wifi_manager = wifi_manager
        self.bluetooth_manager = bluetooth_manager
        self.display_controller = display_controller

        self._app = None
        self._server = None
        self._running = False

    async def start(self) -> None:
        """Start the web server."""
        log.info(f"Starting web server on {self.host}:{self.port}")
        self._running = True

        try:
            # Try to use uvicorn if available
            import uvicorn
            from fastapi import FastAPI
            from fastapi.responses import JSONResponse

            self._app = FastAPI(
                title="Eye Remote API",
                version="2.1.0",
                docs_url="/api/docs",
            )

            @self._app.get("/api/health")
            async def health():
                return {"status": "ok", "version": "2.1.0"}

            @self._app.get("/api/metrics")
            async def metrics():
                return {
                    "mode": self.mode_manager.current_mode.value if self.mode_manager else "unknown",
                    "failover": self.failover_monitor.state.value if self.failover_monitor else "unknown",
                }

            @self._app.get("/api/config")
            async def get_config():
                if self.config:
                    return {"device_id": self.config.device.id}
                return {"error": "no config"}

            # Run uvicorn in background
            config = uvicorn.Config(
                self._app,
                host=self.host,
                port=self.port,
                log_level="warning",
            )
            self._server = uvicorn.Server(config)
            asyncio.create_task(self._server.serve())
            log.info(f"Web server started on http://{self.host}:{self.port}")

        except ImportError:
            log.warning("uvicorn/fastapi not available - web server disabled")
        except Exception as e:
            log.error(f"Failed to start web server: {e}")

    async def stop(self) -> None:
        """Stop the web server."""
        log.info("Stopping web server")
        self._running = False
        if self._server:
            self._server.should_exit = True
