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
import os
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Header, Request, Response

VERSION = "1.0.6"
CTL = shutil.which("autheliactl") or "/usr/sbin/autheliactl"

# Authelia LXC (provisioned by install-lxc.sh at 10.100.0.20:9091). Override
# via SECUBOX_AUTHELIA_URL if the LXC IP/port differs (e.g. for tests).
AUTHELIA_URL = os.environ.get("SECUBOX_AUTHELIA_URL", "http://10.100.0.20:9091")
# Authelia headers worth forwarding back to nginx (and through to the
# protected backend). nginx auth_request can capture these via
# `auth_request_set $sbx_user $upstream_http_remote_user;` etc.
_AUTH_REMOTE_HEADERS = (
    "Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name",
)

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
@app.head("/verify")
def verify(
    request: Request,
    response: Response,
    authorization: str | None = Header(default=None),
    cookie: str | None = Header(default=None),
) -> Response:
    """
    nginx `auth_request` target.

    Reverse-proxies to Authelia's native /api/verify which:
      - validates the `authelia_session` cookie against the session store
      - returns 200 + Remote-User / Remote-Groups / Remote-Email headers
        when the session is valid
      - returns 401 otherwise

    We propagate those Remote-* headers back to nginx so the protected
    backend's `proxy_set_header` can capture them via
    `auth_request_set $sbx_user $upstream_http_remote_user;` (etc).
    """
    # Pass through Cookie + Authorization headers to Authelia. nginx already
    # stripped the request body (proxy_pass_request_body off) so we're just
    # forwarding metadata.
    # Authelia 4.39+ is path-prefixed at /auth (server.address). The verify
    # endpoint is therefore at /auth/api/verify (both /api/verify legacy
    # and the prefixed path respond, but prefix is the canonical one).
    upstream = f"{AUTHELIA_URL.rstrip('/')}/auth/api/verify"
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    if authorization:
        headers["Authorization"] = authorization

    req = urllib.request.Request(upstream, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            status_code = r.status
            for h in _AUTH_REMOTE_HEADERS:
                v = r.headers.get(h)
                if v is not None:
                    response.headers[h] = v
    except urllib.error.HTTPError as e:
        # Authelia returned a non-2xx (typically 401). Propagate the code so
        # nginx's `error_page 401 = @sbx_auth_login;` can fire.
        return Response(status_code=e.code)
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        # Authelia LXC unreachable — fail closed (deny by default).
        raise HTTPException(
            status_code=503,
            detail=f"authelia upstream unreachable: {e!r}",
        )

    # 2xx from Authelia → authenticated. Return 200 (with the Remote-* headers
    # already written into `response`).
    response.status_code = 200 if status_code < 300 else status_code
    return response
