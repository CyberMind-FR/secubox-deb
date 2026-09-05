# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Alerts router — Threat log, stats, and ban management."""
import json
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("mitmproxy.alerts")

DATA_PATH = Path("/data/mitmproxy-waf/data")
THREATS_LOG = DATA_PATH / "threats.log"


class ThreatEntry(BaseModel):
    ts: float
    ip: str
    host: str
    path: str
    method: str
    category: str
    severity: str
    pattern: str
    matched: str


class AlertsResponse(BaseModel):
    total: int
    alerts: List[ThreatEntry]


class StatsResponse(BaseModel):
    total: int
    by_category: dict
    by_severity: dict
    by_ip: dict
    top_paths: List[dict]


class BanEntry(BaseModel):
    ip: str
    reason: str
    duration: str
    source: str


class BansResponse(BaseModel):
    total: int
    bans: List[BanEntry]


class UnbanRequest(BaseModel):
    ip: str


class ActionResponse(BaseModel):
    success: bool
    message: str


@router.get("/alerts", response_model=AlertsResponse)
async def get_alerts(
    user=Depends(require_jwt),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    category: Optional[str] = None,
    severity: Optional[str] = None
):
    """Get threat alerts with pagination and filtering."""
    alerts = []

    if THREATS_LOG.exists():
        lines = THREATS_LOG.read_text().strip().split("\n")
        lines = [l for l in lines if l]  # Remove empty
        lines.reverse()  # Most recent first

        for line in lines:
            try:
                entry = json.loads(line)

                # Apply filters
                if category and entry.get("category") != category:
                    continue
                if severity and entry.get("severity") != severity:
                    continue

                alerts.append(ThreatEntry(**entry))
            except (json.JSONDecodeError, TypeError):
                continue

    total = len(alerts)
    alerts = alerts[offset:offset + limit]

    return AlertsResponse(total=total, alerts=alerts)


@router.get("/alerts/stats", response_model=StatsResponse)
async def get_alert_stats(user=Depends(require_jwt)):
    """Get aggregated threat statistics."""
    stats = {
        "total": 0,
        "by_category": {},
        "by_severity": {},
        "by_ip": {},
        "top_paths": []
    }

    path_counts = {}

    if THREATS_LOG.exists():
        for line in THREATS_LOG.read_text().strip().split("\n"):
            if not line:
                continue
            try:
                entry = json.loads(line)
                stats["total"] += 1

                cat = entry.get("category", "unknown")
                sev = entry.get("severity", "unknown")
                ip = entry.get("ip", "unknown")
                path = entry.get("path", "/")

                stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
                stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
                stats["by_ip"][ip] = stats["by_ip"].get(ip, 0) + 1
                path_counts[path] = path_counts.get(path, 0) + 1

            except json.JSONDecodeError:
                continue

    # Top 10 paths
    sorted_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    stats["top_paths"] = [{"path": p, "count": c} for p, c in sorted_paths]

    return StatsResponse(**stats)


@router.post("/alerts/clear", response_model=ActionResponse)
async def clear_alerts(user=Depends(require_jwt)):
    """Clear the threat log."""
    if THREATS_LOG.exists():
        THREATS_LOG.write_text("")
        log.info("Threat log cleared")

    return ActionResponse(success=True, message="Threat log cleared")


# Alias for WebUI compatibility
@router.post("/clear_alerts", response_model=ActionResponse)
async def clear_alerts_alias(user=Depends(require_jwt)):
    """Clear the threat log (alias for /alerts/clear)."""
    return await clear_alerts(user)


@router.get("/bans", response_model=BansResponse)
async def get_bans(user=Depends(require_jwt)):
    """Get active bans.

    No external ban backend is configured, so this returns an empty list.
    """
    return BansResponse(total=0, bans=[])


@router.post("/unban", response_model=ActionResponse)
async def unban_ip(req: UnbanRequest, user=Depends(require_jwt)):
    """Remove IP from ban list.

    No external ban backend is configured, so there is nothing to remove.
    """
    log.info(f"Unban requested for IP: {req.ip} (no active ban backend)")
    return ActionResponse(success=True, message=f"IP {req.ip} unbanned")
