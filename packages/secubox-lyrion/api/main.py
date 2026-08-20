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

from fastapi import Body, Depends, FastAPI, HTTPException, Header, Response

# Les VERBES D'ACTION ajoutes en #993 exigent un jeton. Le reste de cette API
# n'en demande pas — decision anterieure du module, protegee par la porte LAN
# de nginx — mais `upgrade` redemarre le serveur de musique et coupe toute
# lecture en cours : une action de cette portee ne doit pas etre declenchable
# par le simple fait d'etre sur le reseau local. `check-upgrade` sort vers
# l'exterieur, il est gate pour la meme raison.
from secubox_core.auth import require_jwt

VERSION = "1.2.0"
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


# ── Pilotage des lecteurs (style squeezectl, JSON-RPC LMS natif) #1071 ─────────
# Le panneau « lecteurs connectes » detecte deja les Squeezebox/Squeezelite via
# l'API JSON-RPC native de LMS (endpoint /players). On ajoute le CONTROLE avec le
# meme jeu de commandes que baztian/squeezectl, SANS dependance externe : chaque
# verbe est une slim.request adressee au lecteur.
#
# Porte LAN nginx (comme /rescan) et PAS de jeton : piloter une lecture n'est ni
# destructif ni un redemarrage de service (contrairement a `upgrade`). Le `pid`
# part en VALEUR JSON vers LMS (jamais un shell) — pas d'injection ; on valide
# seulement qu'il est non vide et que le volume reste borne.
_ACTIONS_SIMPLES = {
    "play":   ["play"],
    "pause":  ["pause"],
    "stop":   ["stop"],
    "next":   ["playlist", "index", "+1"],
    "prev":   ["playlist", "index", "-1"],
    "unsync": ["sync", "-"],
}


def _exige_pid(pid: str) -> str:
    pid = (pid or "").strip()
    if not pid:
        raise HTTPException(status_code=400, detail="identifiant lecteur requis")
    return pid


@app.post("/player/{pid}/action/{verbe}")
def player_action(pid: str, verbe: str) -> Dict[str, Any]:
    """Transport simple : play / pause / stop / next / prev / unsync."""
    pid = _exige_pid(pid)
    cmd = _ACTIONS_SIMPLES.get(verbe)
    if cmd is None:
        raise HTTPException(
            status_code=400,
            detail=f"action inconnue: {verbe} (attendu: {', '.join(_ACTIONS_SIMPLES)})")
    _lms_rpc(pid, cmd)
    return {"ok": True, "player": pid, "action": verbe}


@app.post("/player/{pid}/power")
def player_power(pid: str, payload: Dict[str, Any] = Body(default=None)) -> Dict[str, Any]:
    """Allume/eteint un lecteur. Corps: {"on": true|false} (defaut true)."""
    pid = _exige_pid(pid)
    on = bool((payload or {}).get("on", True))
    _lms_rpc(pid, ["power", "1" if on else "0"])
    return {"ok": True, "player": pid, "power": on}


@app.post("/player/{pid}/volume")
def player_volume(pid: str, payload: Dict[str, Any] = Body(default=None)) -> Dict[str, Any]:
    """Regle le volume absolu. Corps: {"level": 0..100}."""
    pid = _exige_pid(pid)
    try:
        niveau = int((payload or {}).get("level"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail='corps attendu: {"level": 0..100}')
    if not 0 <= niveau <= 100:
        raise HTTPException(status_code=400, detail="volume hors bornes (0..100)")
    _lms_rpc(pid, ["mixer", "volume", str(niveau)])
    return {"ok": True, "player": pid, "volume": niveau}


@app.post("/player/{pid}/sync")
def player_sync(pid: str, payload: Dict[str, Any] = Body(default=None)) -> Dict[str, Any]:
    """Synchronise un autre lecteur DANS le groupe de celui-ci.

    Corps: {"target": "<playerid>"}. Semantique LMS : `<pid> sync <target>`
    fait rejoindre `target` au lecteur `pid`. Pour desynchroniser, voir
    l'action `unsync`."""
    pid = _exige_pid(pid)
    cible = _exige_pid((payload or {}).get("target", ""))
    _lms_rpc(pid, ["sync", cible])
    return {"ok": True, "player": pid, "sync": cible}


# ── External media library (auto-detect + opt-in confirm) ─────────────────────
# Delegue a `sudo -n lyrionctl medialib …`. Le sudo n'est pas cosmetique :
# /data/lxc/<nom> appartient a l'idmap du conteneur (100000:100000,
# drwxrwx---), donc `secubox` ne peut pas meme le traverser.
# Delegates to `lyrionctl medialib …`, which always emits JSON (even for its
# own error cases). The ctl work — a bounded filesystem scan for `detect`, a
# bind-mount + rescan for `mount` — is blocking, so it runs in a worker thread
# to keep the shared event loop free.
async def _ctl_medialib(*args: str) -> Dict[str, Any]:
    def _run() -> Dict[str, Any]:
        cmd = ["sudo", "-n", CTL, "medialib", *args]
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


# Verbe ctl arbitraire, hors du chemin `medialib`, exécuté hors boucle
# d'événements (#993). `_ctl_json` est synchrone et plafonné à 15 s : suffisant
# pour `status`, pas pour un relevé réseau ni pour un upgrade qui télécharge et
# installe un paquet dans la LXC.
async def _ctl_verb(*args: str, timeout: int = 120) -> Dict[str, Any]:
    def _run() -> Dict[str, Any]:
        try:
            proc = subprocess.run([CTL, *args], capture_output=True, timeout=timeout)
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail=f"lyrionctl not found at {CTL}")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504,
                                detail=f"lyrionctl {' '.join(args)} timed out after {timeout}s")
        out = (proc.stdout or b"").decode()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            err = (proc.stderr or b"").decode()
            raise HTTPException(status_code=500,
                                detail=f"lyrionctl {' '.join(args)} emitted non-JSON: "
                                       f"out={out[:200]!r} err={err[:200]!r}")

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
        # Peripheriques non montes (#993). Rapportes SEPAREMENT : un candidate
        # est un chemin pret a lier, un device demande d'abord un montage hote.
        # Les fondre en une liste ferait proposer au panneau une action qui
        # echouerait sur la moitie des entrees.
        "devices": det.get("devices", []),
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


@app.get("/version-status")
async def version_status() -> Dict[str, Any]:
    """Version installee + derniere version connue, depuis le CACHE.

    Ne sort jamais vers le reseau : `check-upgrade` le fait, une fois par jour,
    par minuteur. Interroger le depot amont dans le chemin de requete rendrait
    l'affichage du panneau dependant d'une panne DNS ou d'un depot lent."""
    return await _ctl_verb("version-status", timeout=20)


@app.post("/check-upgrade")
async def check_upgrade(_: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Releve immediat, a la demande. Sort vers le reseau et rafraichit le
    cache — d'ou un POST : ce n'est pas une lecture sans effet."""
    return await _ctl_verb("check-upgrade", timeout=120)


@app.post("/upgrade")
async def upgrade(_: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Applique la mise a jour dans la LXC.

    DELIBEREMENT manuel : l'operation redemarre le serveur et coupe toute
    lecture en cours. Le minuteur quotidien sert a SAVOIR qu'une version
    existe, jamais a l'appliquer."""
    def _run() -> Dict[str, Any]:
        try:
            proc = subprocess.run([CTL, "upgrade"], capture_output=True, timeout=900)
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="upgrade timed out after 900s")
        out = (proc.stdout or b"").decode()
        if proc.returncode != 0:
            err = (proc.stderr or b"").decode()
            raise HTTPException(status_code=500, detail=(err or out).strip()[:500])
        # `upgrade` n'emet pas de JSON : c'est un flux de progression dpkg. On
        # renvoie ses dernieres lignes plutot que de pretendre le contraire.
        return {"ok": True, "output": out.strip().splitlines()[-3:]}

    return await asyncio.to_thread(_run)


@app.post("/medialib/unmount")
async def medialib_unmount() -> Dict[str, Any]:
    """Remove the external-media RO bind + persisted key, then rescan."""
    return await _ctl_medialib("unmount")
