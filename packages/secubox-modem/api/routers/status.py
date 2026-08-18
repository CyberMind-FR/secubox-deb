# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Modem Status Router
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

API endpoints for modem status, info, and signal monitoring.
"""
from typing import Optional, Dict, Any
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

from core.modem_detect import ModemDetector
from core.mm_client import ModemManagerClient
from core.qmi_client import QMIClient
from core.signal_history import get_signal_history

log = get_logger("modem-status")
router = APIRouter()

# Global instances
_detector: Optional[ModemDetector] = None
_mm_client: Optional[ModemManagerClient] = None
_qmi_client: Optional[QMIClient] = None


def get_detector() -> ModemDetector:
    global _detector
    if _detector is None:
        _detector = ModemDetector()
    return _detector


def get_mm_client() -> ModemManagerClient:
    global _mm_client
    if _mm_client is None:
        _mm_client = ModemManagerClient()
    return _mm_client


def get_qmi_client() -> QMIClient:
    global _qmi_client
    if _qmi_client is None:
        _qmi_client = QMIClient()
    return _qmi_client


# === Response Models ===

class StatusResponse(BaseModel):
    connected: bool
    state: str
    operator_name: str = ""
    access_technology: str = ""
    signal_quality: int = 0
    ip_address: str = ""
    model: str = ""
    imei: str = ""


class InfoResponse(BaseModel):
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    imei: str = ""
    imsi: str = ""
    meid: str = ""


class SignalResponse(BaseModel):
    rssi: Optional[float] = None
    rsrp: Optional[float] = None
    rsrq: Optional[float] = None
    sinr: Optional[float] = None
    quality_percent: Optional[int] = None
    network_type: str = ""
    timestamp: str = ""


# === Endpoints ===

@router.get("/status", response_model=StatusResponse)
async def get_status(user=Depends(require_jwt)):
    """Get current modem and connection status."""
    detector = get_detector()
    mm = get_mm_client()

    modem = await detector.get_modem_via_mmcli()
    status = await mm.get_status()

    return StatusResponse(
        connected=status.connected,
        state=status.state,
        operator_name=status.operator_name,
        access_technology=status.access_technology,
        signal_quality=status.signal_quality,
        ip_address=status.ip_address,
        model=modem.model if modem else "",
        imei=modem.equipment_id if modem else "",
    )


@router.get("/info", response_model=InfoResponse)
async def get_info(user=Depends(require_jwt)):
    """Get modem device information."""
    qmi = get_qmi_client()
    info = await qmi.get_device_info()

    return InfoResponse(
        manufacturer=info.get("manufacturer", ""),
        model=info.get("model", ""),
        firmware=info.get("firmware", ""),
        imei=info.get("imei", ""),
        imsi="",  # Not available via QMI without SIM unlock
        meid=info.get("meid", ""),
    )


@router.get("/signal", response_model=SignalResponse)
async def get_signal(user=Depends(require_jwt)):
    """Get current signal strength metrics."""
    mm = get_mm_client()
    signal = await mm.get_signal_info()

    # Prefer LTE values if available
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

    # Calculate quality percentage from RSRP if available
    quality_percent = None
    if rsrp is not None:
        # RSRP: -140 dBm (poor) to -44 dBm (excellent)
        quality_percent = max(0, min(100, int((rsrp + 140) / 96 * 100)))

    # Store measurement
    history = get_signal_history()
    await history.add_measurement(
        rssi=rssi,
        rsrp=rsrp,
        rsrq=rsrq,
        sinr=sinr,
        quality_percent=quality_percent,
        network_type=network_type,
    )

    return SignalResponse(
        rssi=rssi,
        rsrp=rsrp,
        rsrq=rsrq,
        sinr=sinr,
        quality_percent=quality_percent,
        network_type=network_type,
        timestamp=datetime.now().isoformat(),
    )


@router.get("/signal/history")
async def get_signal_history_endpoint(
    minutes: int = Query(default=60, le=120),
    limit: int = Query(default=0, le=1000),
    user=Depends(require_jwt)
):
    """Get signal history for graphing."""
    history = get_signal_history()
    records = await history.get_history(minutes=minutes, limit=limit)
    stats = await history.get_stats(minutes=minutes)

    return {
        "records": records,
        "stats": stats,
        "period_minutes": minutes,
    }


@router.get("/signal/stats")
async def get_signal_stats(
    minutes: int = Query(default=60, le=120),
    user=Depends(require_jwt)
):
    """Get signal statistics."""
    history = get_signal_history()
    return await history.get_stats(minutes=minutes)


@router.get("/detection")
async def get_detection(user=Depends(require_jwt)):
    """Get modem detection summary."""
    detector = get_detector()
    return await detector.get_modem_summary()


@router.get("/sim")
async def get_sim_info(user=Depends(require_jwt)):
    """Get SIM card information."""
    mm = get_mm_client()
    return await mm.get_sim_info()


@router.get("/network")
async def get_network_info(user=Depends(require_jwt)):
    """Get network registration and serving system info."""
    qmi = get_qmi_client()

    serving = await qmi.get_serving_system()
    home = await qmi.get_home_network()
    cell = await qmi.get_cell_location()
    bands = await qmi.get_rf_band_info()

    return {
        "serving_system": serving,
        "home_network": home,
        "cell_location": cell,
        "rf_bands": bands,
    }
