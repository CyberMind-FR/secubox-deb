# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-grafana — host control plane API.

FastAPI exposed on /run/secubox/grafana.sock and proxied by nginx at
/api/v1/grafana/. Mandatory endpoints per docs/MODULE-GUIDELINES.md §8:
status, components, access, healthz, version.

Module-specific endpoints (dashboard/datasource/...) shell out to
grafanactl --json to keep a single source of truth (#230 task G4).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException

VERSION = "1.0.0"
CTL = shutil.which("grafanactl") or "/usr/sbin/grafanactl"

app = FastAPI(
    title="SecuBox Grafana",
    version=VERSION,
    docs_url=None,           # admin UIs go through the SecuBox WebUI
    redoc_url=None,
    openapi_url=None,
)


def _ctl_json(*args: str) -> Dict[str, Any]:
    """Call grafanactl <args> --json and parse the JSON output."""
    cmd = [CTL, *args, "--json"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=15)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"grafanactl failed: {e.output!r}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"grafanactl not found at {CTL}")
    try:
        return json.loads(out.decode())
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"grafanactl emitted non-JSON: {e}; raw={out!r}")


@app.get("/healthz")
def healthz() -> Dict[str, bool]:
    """Liveness probe: only checks that this API process is up."""
    return {"ok": True}


@app.get("/version")
def version() -> Dict[str, str]:
    build_file = Path("/usr/share/doc/secubox-grafana/.build-sha")
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
