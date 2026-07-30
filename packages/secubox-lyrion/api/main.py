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

import asyncio
import json
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from fastapi import Body, FastAPI, HTTPException, Header, Response

VERSION = "1.1.0"
CTL = shutil.which("lyrionctl") or "/usr/sbin/lyrionctl"

# LMS jsonrpc endpoint inside the LXC. Used for live data the lyrionctl
# CLI does not expose (players list, now-playing, scan trigger).
LMS_JSONRPC = os.environ.get(
    "SECUBOX_LYRION_LMS_JSONRPC",
    "http://10.100.0.100:9000/jsonrpc.js",
)


def _lms_rpc(player: str, command: List[Any], timeout: float = 5.0) -> Dict[str, Any]:
    """POST a slim.request to the LMS JSON-RPC endpoint.

    `player` is the player MAC/id ('' for server-level commands).
    `command` is the list form of the CLI (e.g. ['players', '0', '99']).
    Returns the parsed 'result' dict, or {} on any failure (callers
    decide whether absence is an error or just an empty state)."""
    body = json.dumps({
        "id": 1, "method": "slim.request",
        "params": [player, command],
    }).encode()
    req = urllib.request.Request(
        LMS_JSONRPC, data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode())
            return payload.get("result", {}) or {}
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return {}

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


@app.get("/players")
def players() -> Dict[str, Any]:
    """List players connected to LMS — name, model, id (MAC), ip, power.

    Hits LMS JSON-RPC ['players', '0', '99']. Returns {"players": [...]}
    so the admin webui can render a table even when the list is empty
    (which is the common case: 0 players usually means a hardware
    Squeezebox is on a different L2 segment and broadcast discovery
    isn't crossing — see the hint in the admin page)."""
    res = _lms_rpc("", ["players", "0", "99"])
    items = res.get("players_loop", []) if isinstance(res, dict) else []
    out = [
        {
            "id": p.get("playerid", ""),
            "name": p.get("name", ""),
            "model": p.get("modelname") or p.get("model") or "—",
            "ip": p.get("ip", ""),
            "power": bool(p.get("power", 0)),
        }
        for p in items
    ]
    return {"players": out, "count": len(out)}


@app.get("/now-playing")
def now_playing() -> Dict[str, Any]:
    """Track currently playing on any player. Empty dict if nothing is
    playing on any connected player (or if no player is connected)."""
    plist = _lms_rpc("", ["players", "0", "99"]).get("players_loop", []) or []
    for p in plist:
        if not p.get("power"):
            continue
        pid = p.get("playerid")
        if not pid:
            continue
        status_res = _lms_rpc(pid, ["status", "-", "1", "tags:aladKN"])
        playlist = status_res.get("playlist_loop", []) if isinstance(status_res, dict) else []
        if not playlist:
            continue
        track = playlist[0]
        if status_res.get("mode") == "play":
            return {
                "title":  track.get("title", ""),
                "artist": track.get("artist", "") or track.get("trackartist", ""),
                "album":  track.get("album", ""),
                "player": p.get("name", pid),
                "mode":   "play",
            }
    return {}


@app.post("/rescan")
def rescan() -> Dict[str, Any]:
    """Trigger an LMS library rescan. Returns {"ok": True} when the
    request was accepted by LMS (the scan runs in the background and
    can take minutes on a large library)."""
    res = _lms_rpc("", ["rescan"])
    # LMS returns {} on success for rescan — empty result is a positive
    # ack as long as the RPC round-trip succeeded.
    return {"ok": True, "result": res}


# ── External media library (auto-detect + opt-in confirm) ─────────────────────
# Delegates to `lyrionctl medialib …`, which always emits JSON (even for its
# own error cases). The ctl work — a bounded filesystem scan for `detect`, a
# bind-mount + rescan for `mount` — is blocking, so it runs in a worker thread
# to keep the shared event loop free.
async def _ctl_medialib(*args: str) -> Dict[str, Any]:
    def _run() -> Dict[str, Any]:
        cmd = [CTL, "medialib", *args]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=90)
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail=f"lyrionctl not found at {CTL}")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="lyrionctl medialib timed out")
        out = proc.stdout.decode() if proc.stdout else ""
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            err = proc.stderr.decode() if proc.stderr else ""
            raise HTTPException(
                status_code=500,
                detail=f"medialib emitted non-JSON: out={out!r} err={err!r}",
            )

    return await asyncio.to_thread(_run)


@app.get("/medialib")
async def medialib() -> Dict[str, Any]:
    """Current external-media mount + detected candidates.

    Combines `medialib status` (the persisted/live mount) with
    `medialib detect` (audio-containing external mountpoints). Detection
    NEVER mounts — the webui offers an explicit opt-in per candidate."""
    st = await _ctl_medialib("status")
    det = await _ctl_medialib("detect")
    return {
        "external": st.get("external"),
        "mounted": bool(st.get("mounted")),
        "candidates": det.get("candidates", []),
    }


@app.post("/medialib/mount")
async def medialib_mount(payload: Dict[str, Any] = Body(default=None)) -> Dict[str, Any]:
    """Read-only-bind a confirmed host path into the Lyrion LXC.

    Body: {"path": "<host path>"}. The path must already appear as a
    detected candidate the operator confirmed in the UI."""
    path = (payload or {}).get("path", "")
    if not isinstance(path, str) or not path.strip():
        raise HTTPException(status_code=400, detail='body must be {"path": "<host path>"}')
    return await _ctl_medialib("mount", path)


@app.post("/medialib/unmount")
async def medialib_unmount() -> Dict[str, Any]:
    """Remove the external-media RO bind + persisted key, then rescan."""
    return await _ctl_medialib("unmount")
