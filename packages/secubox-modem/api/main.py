# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Modem API
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

FastAPI application for Quectel LTE/5G modem management.

Features:
  - Auto-detect any plugged Quectel modem (EC25, RM500Q, etc.)
  - Data connection management (APN, connect/disconnect)
  - SMS send/receive via WebUI
  - AT command console (interactive WebSocket terminal)
  - Signal strength monitoring with graphs
  - Firmware/device info display
  - Hybrid approach: ModemManager + qmicli
"""
import asyncio
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, Depends
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

from .routers import status, connection, sms, terminal
from core.modem_detect import ModemDetector
from core.mm_client import ModemManagerClient
from core.signal_history import get_signal_history

log = get_logger("modem")

# Version
__version__ = "1.0.0"

# ═══════════════════════════════════════════════════════════════════════
# Background Tasks
# ═══════════════════════════════════════════════════════════════════════

_signal_collector_task: Optional[asyncio.Task] = None
_detector: Optional[ModemDetector] = None
_mm_client: Optional[ModemManagerClient] = None


async def _periodic_signal_collector():
    """Background task to collect signal strength every 30 seconds."""
    global _mm_client

    if _mm_client is None:
        _mm_client = ModemManagerClient()

    history = get_signal_history()

    while True:
        try:
            await asyncio.sleep(30)

            # Get signal info from ModemManager
            signal = await _mm_client.get_signal_info()
            status = await _mm_client.get_status()

            # Extract values
            lte = signal.get("lte", {})
            nr5g = signal.get("nr5g", {})

            rssi = None
            rsrp = None
            rsrq = None
            sinr = None
            network_type = ""

            if lte and any(v is not None for v in lte.values()):
                rssi = lte.get("rssi")
                rsrp = lte.get("rsrp")
                rsrq = lte.get("rsrq")
                sinr = lte.get("snr")
                network_type = "LTE"
            elif nr5g and any(v is not None for v in nr5g.values()):
                rsrp = nr5g.get("rsrp")
                rsrq = nr5g.get("rsrq")
                sinr = nr5g.get("snr")
                network_type = "5G NR"

            # Use CSQ quality as fallback
            quality_percent = status.signal_quality if status.signal_quality > 0 else None

            # Calculate from RSRP if available
            if rsrp is not None:
                quality_percent = max(0, min(100, int((rsrp + 140) / 96 * 100)))

            # Store measurement
            await history.add_measurement(
                rssi=rssi,
                rsrp=rsrp,
                rsrq=rsrq,
                sinr=sinr,
                quality_percent=quality_percent,
                network_type=network_type,
                operator=status.operator_name,
            )

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("Signal collector error: %s", e)


# ═══════════════════════════════════════════════════════════════════════
# FastAPI Application
# ═══════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="secubox-modem",
    version=__version__,
    description="Quectel LTE/5G modem management for SecuBox",
    root_path="/api/v1/modem",
)

# Auth router
app.include_router(auth_router, prefix="/auth")

# Module routers
app.include_router(status.router, tags=["status"])
app.include_router(connection.router, tags=["connection"])
app.include_router(sms.router, tags=["sms"])
app.include_router(terminal.router, tags=["terminal"])


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _signal_collector_task

    log.info("SecuBox Modem API starting, version %s", __version__)

    # Start signal collector
    _signal_collector_task = asyncio.create_task(_periodic_signal_collector())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks and cleanup."""
    global _signal_collector_task

    log.info("SecuBox Modem API shutting down")

    if _signal_collector_task:
        _signal_collector_task.cancel()
        try:
            await _signal_collector_task
        except asyncio.CancelledError:
            pass

    # Flush signal history
    history = get_signal_history()
    await history.flush()


# ═══════════════════════════════════════════════════════════════════════
# Core Endpoints
# ═══════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    """Health check endpoint (no auth required)."""
    global _detector

    if _detector is None:
        _detector = ModemDetector()

    modem = await _detector.get_modem_via_mmcli()

    return {
        "status": "ok",
        "module": "modem",
        "version": __version__,
        "modem_detected": modem is not None,
        "modem_model": modem.model if modem else None,
    }


@app.get("/components")
async def components():
    """List system components (three-fold: what)."""
    return {
        "components": [
            {
                "name": "ModemManager",
                "description": "System modem management daemon",
                "required": True,
            },
            {
                "name": "libqmi-utils",
                "description": "QMI protocol utilities (qmicli)",
                "required": False,
            },
            {
                "name": "picocom",
                "description": "Serial terminal for AT commands",
                "required": False,
            },
            {
                "name": "Quectel Modem",
                "description": "LTE/5G modem hardware (EC25, RM500Q, etc.)",
                "required": True,
            },
        ]
    }


@app.get("/access")
async def access():
    """Show access endpoints (three-fold: how)."""
    return {
        "endpoints": [
            {
                "name": "WebUI Dashboard",
                "url": "/modem/",
                "description": "Browser-based modem management interface",
            },
            {
                "name": "REST API",
                "url": "/api/v1/modem/",
                "description": "RESTful API for automation",
            },
            {
                "name": "AT Console",
                "url": "ws://host/api/v1/modem/at/console",
                "description": "WebSocket AT command terminal",
            },
        ]
    }


@app.get("/summary")
async def get_summary(user=Depends(require_jwt)):
    """Get comprehensive modem summary."""
    global _detector, _mm_client

    if _detector is None:
        _detector = ModemDetector()
    if _mm_client is None:
        _mm_client = ModemManagerClient()

    modem = await _detector.get_modem_via_mmcli()
    conn_status = await _mm_client.get_status()
    signal = await _mm_client.get_signal_info()
    history = get_signal_history()
    stats = await history.get_stats(minutes=60)

    return {
        "modem": {
            "detected": modem is not None,
            "model": modem.model if modem else None,
            "manufacturer": modem.manufacturer if modem else None,
            "imei": modem.equipment_id if modem else None,
            "state": modem.state if modem else None,
        },
        "connection": {
            "connected": conn_status.connected,
            "state": conn_status.state,
            "operator": conn_status.operator_name,
            "technology": conn_status.access_technology,
            "ip_address": conn_status.ip_address,
        },
        "signal": {
            "quality": conn_status.signal_quality,
            "lte": signal.get("lte"),
            "nr5g": signal.get("nr5g"),
        },
        "history_stats": stats,
        "timestamp": datetime.now().isoformat(),
    }
