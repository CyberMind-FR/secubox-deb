"""secubox-crowdsec — decisions router"""
from fastapi import APIRouter, Depends, Query
import httpx
from secubox_core.auth   import require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

router = APIRouter()
log    = get_logger("crowdsec")


def _headers():
    return {"X-Api-Key": get_config("crowdsec").get("lapi_key", "")}

def _base():
    return get_config("crowdsec").get("lapi_url", "http://127.0.0.1:8080")


@router.get("/decisions")
async def decisions(
    limit: int  = Query(1000, ge=1, le=10000),
    scope: str  = Query("Ip"),
    type_: str  = Query("ban", alias="type"),
):
    """Get decisions for dashboard (public). Returns total count."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            # Get total count first (unlimited)
            r_count = await c.get(f"{_base()}/v1/decisions",
                            headers=_headers(),
                            params={"limit": 10000, "scope": scope, "type": type_})
            all_data = r_count.json() or []
            total = len(all_data) if isinstance(all_data, list) else 0

            # Return paginated results with total
            data = all_data[:limit] if isinstance(all_data, list) else []
            return {"decisions": data, "total": total}
    except Exception as e:
        log.warning("decisions: %s", e)
        return {"decisions": [], "total": 0}


@router.get("/stats")
async def stats(_user=Depends(require_jwt)):
    """Nombre de bans actifs par scope."""
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{_base()}/v1/decisions?limit=5000", headers=_headers())
        data = r.json() or []
    by_type: dict = {}
    for d in (data if isinstance(data, list) else []):
        t = d.get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1
    return {"total": len(data) if isinstance(data, list) else 0, "by_type": by_type}
