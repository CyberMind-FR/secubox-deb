# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-authelia — host control plane API.

FastAPI on /run/secubox/authelia.sock, proxied by nginx at /api/v1/authelia/.
Mandatory endpoints per docs/MODULE-GUIDELINES.md §8.

Plus the `verify` endpoint used as the nginx `auth_request` target for the
SSO-less backends (yacy / rustdesk-web / mitmproxy-web): see #239 SSO bridge
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
CTL = shutil.which("autheliactl") or "/usr/sbin/autheliactl"

app = FastAPI(
    title="SecuBox Authelia",
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
        raise HTTPException(status_code=500, detail=f"autheliactl failed: {e.output!r}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"autheliactl not found at {CTL}")
    try:
        return json.loads(out.decode())
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"autheliactl emitted non-JSON: {e}; raw={out!r}")


@app.get("/healthz")
def healthz() -> Dict[str, bool]:
    return {"ok": True}


@app.get("/version")
def version() -> Dict[str, str]:
    build_file = Path("/usr/share/doc/secubox-authelia/.build-sha")
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


@app.get("/verify")
def verify(
    response: Response,
    authorization: str | None = Header(default=None),
    cookie: str | None = Header(default=None),
) -> Dict[str, Any]:
    """
    nginx `auth_request` target for SSO-less backends.

    Returns 200 + X-Sbx-User / X-Sbx-Role headers if the SecuBox JWT is valid.
    Returns 401 otherwise.

    Stub for v1.0.0 — full JWT validation lives in secubox-portal/api/main.py
    today. This endpoint reverse-proxies to the portal's existing /verify or
    re-implements the JWT check locally; the v1.1.0 plan is to consolidate
    into a shared secubox-core helper.
    """
    # TODO v1.1.0: validate JWT against /etc/secubox/secubox.conf:[api].jwt_secret
    # For now, this endpoint is a stub that returns 401 — wire to secubox-portal
    # /api/v1/portal/verify once that endpoint exists (see #239 spec §Phase A).
    raise HTTPException(status_code=501, detail="auth_request /verify not yet wired — see #239 Phase A")
