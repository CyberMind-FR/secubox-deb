# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-crowdsec — alerts router"""
import subprocess
import json
from fastapi import APIRouter, Depends, Query
from secubox_core.auth import require_jwt

router = APIRouter()


@router.get("/alerts")
async def alerts(
    limit: int = Query(50, ge=1, le=500),
    since: str = Query("24h"),
):
    """Get alerts for dashboard (public)."""
    try:
        r = subprocess.run(
            f"sudo cscli alerts list -o json --limit {limit} --since {since}",
            shell=True, capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout)
            # Transform to simpler format for dashboard
            alerts_list = []
            for alert in (data if isinstance(data, list) else []):
                source_ip = ""
                country = ""

                # Primary: get IP from source object
                source = alert.get("source") or {}
                source_ip = source.get("ip") or source.get("value") or ""

                # Secondary: extract from events metadata if available
                events = alert.get("events") or []
                for event in events:
                    for meta in (event.get("meta") or []):
                        if meta.get("key") == "source_ip" and not source_ip:
                            source_ip = meta.get("value", "")
                        if meta.get("key") == "IsoCode":
                            country = meta.get("value", "")
                    if source_ip and country:
                        break

                # Get country from decisions if not in events
                if not country:
                    for dec in (alert.get("decisions") or []):
                        if dec.get("origin") == "CAPI":
                            country = "CAPI"
                            break

                alerts_list.append({
                    "id": alert.get("id"),
                    "created_at": alert.get("created_at"),
                    "scenario": alert.get("scenario") or alert.get("message") or "unknown",
                    "source_ip": source_ip,
                    "country": country,
                    "events_count": alert.get("events_count") or len(events),
                    "decisions": alert.get("decisions") or []
                })
            return {"alerts": alerts_list}
    except Exception as e:
        return {"alerts": [], "error": str(e)}
    return {"alerts": []}


@router.get("/secubox_logs")
async def secubox_logs(lines: int = Query(100), user=Depends(require_jwt)):
    """Dernières lignes du log CrowdSec."""
    from pathlib import Path
    log_path = Path("/var/log/crowdsec/crowdsec.log")
    if log_path.exists():
        r = subprocess.run(["tail", "-n", str(lines), str(log_path)],
                           capture_output=True, text=True)
        return {"lines": r.stdout.splitlines()}
    # Fallback journald
    r = subprocess.run(
        ["journalctl", "-u", "crowdsec", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True
    )
    return {"lines": r.stdout.splitlines()}
