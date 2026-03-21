"""secubox-crowdsec — bouncers + machines"""
from fastapi import APIRouter, Depends
import httpx
from secubox_core.auth   import require_jwt
from secubox_core.config import get_config

router = APIRouter()
def _h(): return {"X-Api-Key": get_config("crowdsec").get("lapi_key", "")}
def _b(): return get_config("crowdsec").get("lapi_url", "http://127.0.0.1:8080")


@router.get("/bouncers")
async def bouncers():
    """Get bouncers for dashboard (public)."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{_b()}/v1/bouncers", headers=_h())
            data = r.json() or []
            return {"bouncers": data if isinstance(data, list) else []}
    except Exception:
        return {"bouncers": []}


@router.get("/machines")
async def machines(user=Depends(require_jwt)):
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{_b()}/v1/watchers", headers=_h())
        return r.json() or []
