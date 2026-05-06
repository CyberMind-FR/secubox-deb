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
            alerts = []
            for alert in (data if isinstance(data, list) else []):
                source_ip = ""
                country = ""
                # Extract source_ip and country from events metadata
                for event in alert.get("events", []):
                    for meta in event.get("meta", []):
                        if meta.get("key") == "source_ip":
                            source_ip = meta.get("value", "")
                        if meta.get("key") == "IsoCode":
                            country = meta.get("value", "")
                    if source_ip:
                        break
                
                alerts.append({
                    "id": alert.get("id"),
                    "created_at": alert.get("created_at"),
                    "scenario": alert.get("scenario"),
                    "source_ip": source_ip or alert.get("source", {}).get("ip", ""),
                    "country": country,
                    "events_count": len(alert.get("events", [])),
                    "decisions": alert.get("decisions", [])
                })
            return {"alerts": alerts}
    except Exception:
        pass
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
