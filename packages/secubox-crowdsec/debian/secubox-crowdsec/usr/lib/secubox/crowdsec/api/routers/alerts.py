"""secubox-crowdsec — alerts router"""
from fastapi import APIRouter, Depends, Query
import httpx
from secubox_core.auth   import require_jwt
from secubox_core.config import get_config

router = APIRouter()

def _h(): return {"X-Api-Key": get_config("crowdsec").get("lapi_key", "")}
def _b(): return get_config("crowdsec").get("lapi_url", "http://127.0.0.1:8080")


@router.get("/alerts")
async def alerts(
    limit: int = Query(50, ge=1, le=500),
    since: str = Query("24h"),
):
    """Get alerts for dashboard (public)."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_b()}/v1/alerts",
                            headers=_h(),
                            params={"limit": limit, "since": since})
            data = r.json() or []
            return {"alerts": data if isinstance(data, list) else []}
    except Exception:
        return {"alerts": []}


@router.get("/secubox_logs")
async def secubox_logs(lines: int = Query(100), user=Depends(require_jwt)):
    """Dernières lignes du log CrowdSec."""
    import subprocess
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
