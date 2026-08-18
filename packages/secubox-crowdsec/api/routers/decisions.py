# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-crowdsec — decisions router"""
from fastapi import APIRouter, Depends, Query
import httpx
import time
from secubox_core.auth   import require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

router = APIRouter()
log    = get_logger("crowdsec")

# Simple cache to avoid hammering LAPI
_cache = {"data": [], "total": 0, "ts": 0}
CACHE_TTL = 60  # seconds


def _headers():
    return {"X-Api-Key": get_config("crowdsec").get("lapi_key", "")}

def _base():
    return get_config("crowdsec").get("lapi_url", "http://127.0.0.1:8080")


async def _fetch_decisions_cached():
    """Fetch and cache unique decisions (local only, not CAPI)."""
    global _cache
    now = time.time()

    if now - _cache["ts"] < CACHE_TTL and _cache["data"]:
        return _cache["data"], _cache["total"]

    try:
        async with httpx.AsyncClient(timeout=10) as c:
            # Fetch local decisions only (limit 500 for performance)
            r = await c.get(f"{_base()}/v1/decisions",
                            headers=_headers(),
                            params={"limit": 500, "scope": "Ip", "type": "ban"})
            all_data = r.json() or []
            if not isinstance(all_data, list):
                all_data = []

            # Deduplicate by value (IP)
            seen = set()
            unique = []
            for d in all_data:
                val = d.get("value")
                if val and val not in seen:
                    seen.add(val)
                    unique.append(d)

            _cache["data"] = unique
            _cache["total"] = len(unique)
            _cache["ts"] = now
            return unique, len(unique)
    except Exception as e:
        log.warning("decisions fetch: %s", e)
        return _cache["data"], _cache["total"]


@router.get("/decisions")
async def decisions(
    limit: int  = Query(200, ge=1, le=500),
):
    """Get unique active decisions for dashboard (public). Cached 60s."""
    try:
        data, total = await _fetch_decisions_cached()
        return {"decisions": data[:limit], "total": total}
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
