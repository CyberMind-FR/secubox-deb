# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-fmrelay — host control plane API.

Spawns rtl_fm | lame and feeds the audio to icecast2 as an MP3 mount;
in parallel runs redsea against the same RTL-SDR output to extract RDS
metadata (PI/PS/RT) and updates the icecast mount's ICY title via
the admin API. Consumed by:

  - secubox-webradio (UI + auto-discovery)
  - Lyrion as a "Favourite" remote URL — LMS plays Icecast streams
    natively and surfaces ICY StreamTitle in the player.

The single RTL-SDR is shared with secubox-sentinelle-gsm (GSM scans +
RDS sweep). Cross-package coordination via _device_busy_reason()
follow-up (issue #377 acceptance criterion).

FastAPI on /run/secubox/fmrelay.sock, proxied by nginx at
/api/v1/fmrelay/.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Body, FastAPI, HTTPException

VERSION = "0.1.0"
CTL = shutil.which("fmrelayctl") or "/usr/sbin/fmrelayctl"

app = FastAPI(
    title="SecuBox FM Relay",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _ctl_json(*args: str) -> Dict[str, Any]:
    """Invoke fmrelayctl with --json and parse the result.

    stderr is captured separately so human-readable log lines from
    `log()` don't pollute the JSON parser on stdout. The captured
    stderr is only surfaced when the call fails."""
    cmd = [CTL, *args, "--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=15, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"fmrelayctl failed: {e.stderr!r}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"fmrelayctl not found at {CTL}")
    try:
        return json.loads(proc.stdout.decode())
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"fmrelayctl non-JSON: {e}; stdout={proc.stdout!r}; stderr={proc.stderr!r}")


def _ctl_text(*args: str) -> str:
    cmd = [CTL, *args]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=15)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"fmrelayctl failed: {e.output!r}")
    return out.decode()


@app.get("/healthz")
def healthz() -> Dict[str, bool]:
    return {"ok": True}


@app.get("/version")
def version() -> Dict[str, str]:
    build_file = Path("/usr/share/doc/secubox-fmrelay/.build-sha")
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
    """Real mount URLs (consumed by Lyrion / webradio / VLC). The admin
    webui's `Open Webradio →` button reads from here per the dual-vhost
    MUST pattern (MODULE-GUIDELINES §4)."""
    return _ctl_json("access")


@app.get("/mounts")
def mounts() -> Dict[str, Any]:
    """List active icecast mounts + listener counts."""
    return _ctl_json("mounts")


@app.get("/now-playing")
def now_playing() -> Dict[str, Any]:
    """Current RDS RadioText for the active relay (or {} if idle)."""
    return _ctl_json("now-playing")


@app.post("/start")
def start(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Body: {freq: "103.9M", mount: "savoie", bitrate?: 128, gain?: 49, ppm?: 60}.

    Returns the spawned runner state. Refuses with 409 if the RTL-SDR
    is held by another module (sentinelle GSM scan, RDS sweep, …)."""
    freq  = (body.get("freq")  or "").strip()
    mount = (body.get("mount") or "").strip()
    if not freq:
        raise HTTPException(status_code=400, detail="freq required (eg '103.9M')")
    if not mount:
        raise HTTPException(status_code=400, detail="mount required (eg 'savoie')")
    args = ["start", freq, "--mount", mount]
    for k in ("bitrate", "gain", "ppm"):
        v = body.get(k)
        if v is not None:
            args.append(f"--{k}")
            args.append(str(v))
    return _ctl_json(*args)


@app.post("/stop")
def stop() -> Dict[str, Any]:
    return _ctl_json("stop")
