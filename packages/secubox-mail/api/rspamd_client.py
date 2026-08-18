# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Thin async wrapper around the Rspamd HTTP controller.

The controller listens on http://10.100.0.10:11334 (the mail LXC).
- Read endpoints (`/stat`, `/history`, `/graph`) accept `Password:` header.
- Write endpoints (`/learnspam`, `/learnham`, `/reload`) accept the same.
- Phase 2 uses one password for both (sourced from
  /etc/secubox/secrets/rspamd-controller.pw).
"""
from __future__ import annotations

import os
import pathlib
from typing import Any

import httpx

_RSPAMD_BASE = os.environ.get("RSPAMD_BASE", "http://10.100.0.10:11334")
_SECRET_PATH = pathlib.Path("/etc/secubox/secrets/rspamd-controller.pw")
_TIMEOUT = httpx.Timeout(5.0, connect=2.0)


def _password() -> str:
    if not _SECRET_PATH.exists():
        return ""
    return _SECRET_PATH.read_text().strip()


def _headers() -> dict:
    pw = _password()
    return {"Password": pw} if pw else {}


async def get(path: str) -> dict[str, Any]:
    """GET `path`. Returns the parsed JSON body or `{error, ...}` on failure."""
    try:
        async with httpx.AsyncClient(base_url=_RSPAMD_BASE, timeout=_TIMEOUT) as c:
            r = await c.get(path, headers=_headers())
            if r.status_code >= 400:
                return {"error": f"rspamd {r.status_code}", "body": r.text[:200]}
            ct = r.headers.get("content-type", "")
            if ct.startswith("application/json"):
                return r.json()
            return {"raw": r.text}
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return {"error": "rspamd unreachable", "detail": str(e)}


async def post(path: str, body: dict | bytes | str | None = None) -> dict[str, Any]:
    """POST `path` with optional `body`."""
    try:
        async with httpx.AsyncClient(base_url=_RSPAMD_BASE, timeout=_TIMEOUT) as c:
            kwargs: dict[str, Any] = {"headers": _headers()}
            if isinstance(body, dict):
                kwargs["json"] = body
            elif body is not None:
                kwargs["content"] = body
            r = await c.post(path, **kwargs)
            if r.status_code >= 400:
                return {"error": f"rspamd {r.status_code}", "body": r.text[:200]}
            ct = r.headers.get("content-type", "")
            if ct.startswith("application/json"):
                return r.json()
            return {"raw": r.text}
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return {"error": "rspamd unreachable", "detail": str(e)}
