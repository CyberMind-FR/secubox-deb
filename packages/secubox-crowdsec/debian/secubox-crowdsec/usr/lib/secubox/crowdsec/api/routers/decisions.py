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
    limit: int  = Query(100, ge=1, le=5000),
    scope: str  = Query("Ip"),
    type_: str  = Query("ban", alias="type"),
):
    """Get decisions for dashboard (public)."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_base()}/v1/decisions",
                            headers=_headers(),
                            params={"limit": limit, "scope": scope, "type": type_})
            data = r.json() or []
            return {"decisions": data if isinstance(data, list) else []}
    except Exception as e:
        log.warning("decisions: %s", e)
        return {"decisions": []}


@router.get("/stats")
async def stats(user=Depends(require_jwt)):
    """Nombre de bans actifs par scope."""
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{_base()}/v1/decisions?limit=5000", headers=_headers())
        data = r.json() or []
    by_type: dict = {}
    for d in (data if isinstance(data, list) else []):
        t = d.get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1
    return {"total": len(data) if isinstance(data, list) else 0, "by_type": by_type}
