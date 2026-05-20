# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-lyrion — host control plane API.

FastAPI on /run/secubox/lyrion.sock, proxied by nginx at /api/v1/lyrion/.
Mandatory endpoints per docs/MODULE-GUIDELINES.md §8.

Plus the `verify` endpoint used as the placeholder for future module-specific endpoints.
SSO-less backends (yacy / rustdesk-web / mitmproxy-web): see #244 SSO bridge
spec.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Header, Response

VERSION = "1.0.0"
CTL = shutil.which("lyrionctl") or "/usr/sbin/lyrionctl"

app = FastAPI(
    title="SecuBox Lyrion",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _ctl_json(*args: str) -> Dict[str, Any]:
    cmd = [CTL, *args, "--json"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=15)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"lyrionctl failed: {e.output!r}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"lyrionctl not found at {CTL}")
    try:
        return json.loads(out.decode())
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"lyrionctl emitted non-JSON: {e}; raw={out!r}")


@app.get("/healthz")
def healthz() -> Dict[str, bool]:
    return {"ok": True}


@app.get("/version")
def version() -> Dict[str, str]:
    build_file = Path("/usr/share/doc/secubox-lyrion/.build-sha")
    build = build_file.read_text().strip() if build_file.is_file() else "unknown"
    return {"version": VERSION, "build": build}


@app.get("/status")
def status() -> Dict[str, Any]:
    return _ctl_json("status")


@app.get("/components")
def components() -> Dict[str, Any]:
    return _ctl_json("components")


@app.get("/access")
def access() -> Dict[str, Any]:
    return _ctl_json("access")


@app.get("/now-playing")
def verify(
    response: Response,
    authorization: str | None = Header(default=None),
    cookie: str | None = Header(default=None),
) -> Dict[str, Any]:
    """
    placeholder for future module-specific endpoints.

    Returns 200 + X-Sbx-User / X-Sbx-Role headers if the SecuBox JWT is valid.
    Returns 401 otherwise.

    Stub for v1.0.0 — full JWT validation lives in secubox-portal/api/main.py
    today. This endpoint reverse-proxies to the portal's existing /now-playing or
    re-implements the JWT check locally; the v1.1.0 plan is to consolidate
    into a shared secubox-core helper.
    """
    # TODO v1.1.0: implement /now-playing aggregator across all connected players,
    # For now, this endpoint is a stub that returns 401 — wire to secubox-portal
    # /api/v1/portal/now-playing once that endpoint exists (see #244 spec §Phase A).
    raise HTTPException(status_code=501, detail="auth_request /now-playing not yet wired — see #244 Phase A")
