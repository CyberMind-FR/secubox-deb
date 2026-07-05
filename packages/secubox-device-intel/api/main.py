# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-device-intel — RETIRED, redirect shim (ref #817)

MAC address whitelist/blacklist + device discovery is now served by
secubox-nac (Client Guardian) — see the Device Guardian consolidation
plan (docs/superpowers/plans/2026-07-05-device-guardian-consolidation.md).

This module is kept only as a thin redirect shim during the deprecation
window: every data route 308-redirects to its secubox-nac equivalent so
old bookmarks/scripts/dashboards keep working while pointing callers at
the new canonical API. Package removal is a separate, gated follow-up —
NOT done here.

Path mapping:
    /status            -> /api/v1/nac/status
    /devices           -> /api/v1/nac/clients
    /device/{mac}      -> /api/v1/nac/client/{mac}
    /whitelist, /allow -> /api/v1/nac/allow
    /blacklist, /deny  -> /api/v1/nac/deny
    /scan              -> /api/v1/nac/scan
    /vendors           -> /api/v1/nac/vendors
    /groups            -> /api/v1/nac/groups
    /export/{fmt}      -> /api/v1/nac/export/{fmt}
    anything else      -> /api/v1/nac/<same path> (fallback catch-all)

/health stays a plain 200 (not redirected) so liveness probes never
308-loop.
"""
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

app = FastAPI(title="secubox-device-intel", version="2.0.0")

_NAC_BASE = "/api/v1/nac"
_DEPRECATED_HEADERS = {"X-SecuBox-Deprecated": "use /api/v1/nac"}
_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]


def _redirect(nac_path: str) -> RedirectResponse:
    """308 (method + body preserving) redirect to the nac equivalent."""
    return RedirectResponse(
        url=f"{_NAC_BASE}{nac_path}",
        status_code=308,
        headers=_DEPRECATED_HEADERS,
    )


@app.get("/health")
async def health_check():
    """Public health check — kept 200 so monitoring doesn't 308-loop."""
    return {"status": "ok", "module": "deb", "deprecated": True}


@app.api_route("/status", methods=_METHODS)
async def status_redirect():
    return _redirect("/status")


@app.api_route("/devices", methods=_METHODS)
async def devices_redirect():
    return _redirect("/clients")


@app.api_route("/device/{mac}", methods=_METHODS)
async def device_redirect(mac: str):
    return _redirect(f"/client/{mac}")


@app.api_route("/whitelist", methods=_METHODS)
async def whitelist_redirect():
    return _redirect("/allow")


@app.api_route("/allow", methods=_METHODS)
async def allow_redirect():
    return _redirect("/allow")


@app.api_route("/blacklist", methods=_METHODS)
async def blacklist_redirect():
    return _redirect("/deny")


@app.api_route("/deny", methods=_METHODS)
async def deny_redirect():
    return _redirect("/deny")


@app.api_route("/scan", methods=_METHODS)
async def scan_redirect():
    return _redirect("/scan")


@app.api_route("/vendors", methods=_METHODS)
async def vendors_redirect():
    return _redirect("/vendors")


@app.api_route("/groups", methods=_METHODS)
async def groups_redirect():
    return _redirect("/groups")


@app.api_route("/export/{fmt}", methods=_METHODS)
async def export_redirect(fmt: str):
    return _redirect(f"/export/{fmt}")


@app.api_route("/{path:path}", methods=_METHODS)
async def catch_all_redirect(path: str):
    return _redirect(f"/{path}" if path else "")
