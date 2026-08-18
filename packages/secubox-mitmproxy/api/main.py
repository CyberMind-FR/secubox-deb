# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox Mitmproxy WAF API

Manages LXC container lifecycle and provides threat monitoring endpoints.
"""
import asyncio
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

from .routers import status_router, settings_router, alerts_router, haproxy_router, waf_router

app = FastAPI(
    title="secubox-mitmproxy",
    version="1.0.0",
    root_path="/api/v1/mitmproxy"
)

# Include auth router
app.include_router(auth_router, prefix="/auth")

# Include module routers
app.include_router(status_router, tags=["status"])
app.include_router(settings_router, tags=["settings"])
app.include_router(alerts_router, tags=["alerts"])
app.include_router(haproxy_router, prefix="/haproxy", tags=["haproxy"])
app.include_router(waf_router, prefix="/waf", tags=["waf"])

log = get_logger("mitmproxy")

# Canonical SecuBox storage (#319) — /data/. Boards previously on /srv/
# are migrated by the dpkg postinst (mv + symlink for back-compat).
DATA_PATH = Path("/data/mitmproxy-waf/data")
STATS_CACHE_FILE = DATA_PATH / "stats.json"
THREATS_LOG = DATA_PATH / "threats.log"

# In-memory cache
_stats_cache: dict = {}


async def _refresh_stats_cache():
    """Background task to refresh stats cache every 60s."""
    global _stats_cache
    while True:
        try:
            stats = {"threats_today": 0, "by_category": {}, "by_severity": {}}

            if THREATS_LOG.exists():
                today_start = __import__("time").time() - 86400

                for line in THREATS_LOG.read_text().strip().split("\n"):
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("ts", 0) >= today_start:
                            stats["threats_today"] += 1
                            cat = entry.get("category", "unknown")
                            sev = entry.get("severity", "unknown")
                            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
                            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
                    except json.JSONDecodeError:
                        continue

            _stats_cache = stats
            STATS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATS_CACHE_FILE.write_text(json.dumps(stats))
            log.debug("Stats cache refreshed")

        except Exception as e:
            log.error(f"Stats cache refresh failed: {e}")

        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Start background tasks."""
    # Load existing cache
    if STATS_CACHE_FILE.exists():
        try:
            global _stats_cache
            _stats_cache = json.loads(STATS_CACHE_FILE.read_text())
        except Exception:
            pass

    asyncio.create_task(_refresh_stats_cache())
    log.info("SecuBox Mitmproxy WAF API started")


@app.get("/health")
async def health():
    """Health check endpoint (no auth required)."""
    return {"status": "ok", "module": "mitmproxy"}


def get_stats_cache() -> dict:
    """Get current stats cache."""
    return _stats_cache
