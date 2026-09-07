# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Freebox TV — streamer on-demand (#1238).

La box est derrière une Freebox : ses chaînes TV sont exposées en RTSP unicast
(`rtsp://mafreebox.freebox.fr/fbxtv_pub/stream?...&service=<N>&flavour=sd`). Un
NAVIGATEUR ne lit pas le RTSP → on interpose un sas ffmpeg **RTSP→HLS** (remux
`-c copy`, aucun ré-encodage, CPU quasi nul), lancé À LA DEMANDE par chaîne et
tué après inactivité. On ne sert QUE ce que la Freebox donne (données réelles),
usage personnel LAN.

Endpoints (servis sous /api/v1/freeboxtv/ via l'agrégateur) :
  GET /health                     — état + nb de chaînes + flux actifs
  GET /channels                   — playlist de base (variante standard)
  GET /hls/{cid}/live.m3u8        — démarre le sas si besoin, sert le manifeste
  GET /hls/{cid}/{seg}            — un segment .ts (ou le m3u8)
"""
from __future__ import annotations

import asyncio
import re
import shutil
import time
import tomllib
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from secubox_core.logger import get_logger

log = get_logger("freeboxtv")

CONFIG_FILE = Path("/etc/secubox/freeboxtv.toml")
DEFAULTS = {
    "playlist_url": "http://mafreebox.freebox.fr/freeboxtv/playlist.m3u",
    "hls_dir": "/run/secubox/freeboxtv/hls",
    "rtsp_transport": "udp",     # la passerelle Freebox sert en RTP/UDP (TCP refusé 461)
    "hls_time": 2,
    "hls_list_size": 6,
    "idle_timeout_s": 45,        # sas tué N s après le dernier accès
    "max_streams": 3,            # garde-fou : nb max de sas ffmpeg simultanés
    "refresh_s": 3600,           # relecture de la playlist Freebox
    "ffmpeg": "/usr/bin/ffmpeg",
}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        if CONFIG_FILE.exists():
            t = tomllib.loads(CONFIG_FILE.read_text())
            for k in DEFAULTS:
                if k in t:
                    cfg[k] = t[k]
    except Exception as e:
        log.error(f"config illisible: {e}")
    return cfg


CFG = load_config()

# id de chaîne = numéro de service Freebox (stable). Segments/manifeste : noms sûrs.
_SEG_RE = re.compile(r"^[A-Za-z0-9._-]+\.(ts|m3u8)$")
_EXT_RE = re.compile(r"#EXTINF:[^,]*,\s*(\d+)\s*-\s*(.+?)\s*\(([^)]+)\)\s*$")


def parse_playlist(text: str) -> dict:
    """M3U Freebox → {cid: {id, lcn, name, url}} pour la seule variante STANDARD (sd)."""
    chans: dict = {}
    lines = text.splitlines()
    for i, l in enumerate(lines):
        m = _EXT_RE.match(l.strip())
        if not m:
            continue
        lcn, name = m.group(1), m.group(2).strip()
        url = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if not url.startswith("rtsp"):
            continue
        sm = re.search(r"service=(\d+)", url)
        fm = re.search(r"flavour=(\w+)", url)
        if not sm or (fm.group(1) if fm else "") != "sd":
            continue                 # une seule entrée par chaîne : la standard
        cid = sm.group(1)
        # On garde la 1re occurrence (ordre playlist = ordre LCN).
        chans.setdefault(cid, {"id": cid, "lcn": int(lcn), "name": name, "url": url})
    return chans


class Streamer:
    """Gère les sas ffmpeg RTSP→HLS : un par chaîne, on-demand, tués si inactifs."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.channels: dict = {}
        self.streams: dict = {}          # cid -> {"proc", "last", "dir"}
        self._lock = asyncio.Lock()
        self.hls_root = Path(cfg["hls_dir"])

    async def refresh_channels(self) -> int:
        try:
            async with httpx.AsyncClient(timeout=10.0) as cli:
                r = await cli.get(self.cfg["playlist_url"])
                if r.status_code == 200:
                    self.channels = parse_playlist(r.text)
        except Exception as e:
            log.error(f"playlist injoignable: {e}")
        return len(self.channels)

    def _dir(self, cid: str) -> Path:
        return self.hls_root / cid

    async def ensure(self, cid: str) -> Optional[Path]:
        """Démarre le sas de la chaîne si besoin ; rend le dossier HLS (ou None)."""
        ch = self.channels.get(cid)
        if not ch:
            return None
        async with self._lock:
            s = self.streams.get(cid)
            if s and s["proc"].returncode is None:
                s["last"] = time.time()
                return s["dir"]
            # Garde-fou : trop de sas actifs → on refuse (le reaper libèrera).
            actifs = [c for c, st in self.streams.items() if st["proc"].returncode is None]
            if len(actifs) >= int(self.cfg["max_streams"]):
                return None
            d = self._dir(cid)
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir(parents=True, exist_ok=True)
            proc = await self._spawn(ch["url"], d)
            self.streams[cid] = {"proc": proc, "last": time.time(), "dir": d}
            return d

    async def _spawn(self, url: str, d: Path):
        args = [
            self.cfg["ffmpeg"], "-hide_banner", "-loglevel", "error",
            "-rtsp_transport", str(self.cfg["rtsp_transport"]),
            "-i", url,
            "-map", "0:v:0", "-map", "0:a:0",     # vidéo + 1 audio (pas le télétexte)
            "-c", "copy",
            # PAS de `-bsf:a aac_adtstoasc` : ce filtre est pour le MP4 (retire les
            # entêtes ADTS). En MPEG-TS/HLS, l'AAC DOIT rester en ADTS, sinon le
            # transmuxeur de hls.js jette une exception (internalException). #1238.
            "-f", "hls",
            "-hls_time", str(self.cfg["hls_time"]),
            "-hls_list_size", str(self.cfg["hls_list_size"]),
            "-hls_flags", "delete_segments+omit_endlist",
            str(d / "live.m3u8"),
        ]
        return await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)

    async def wait_manifest(self, d: Path, timeout: float = 10.0) -> bool:
        """Attend l'apparition du manifeste (le 1er segment met ~2 s à s'écrire)."""
        deadline = time.time() + timeout
        m = d / "live.m3u8"
        while time.time() < deadline:
            if m.exists() and m.stat().st_size > 0:
                return True
            await asyncio.sleep(0.2)
        return False

    def touch(self, cid: str) -> None:
        s = self.streams.get(cid)
        if s:
            s["last"] = time.time()

    async def reaper(self) -> None:
        idle = float(self.cfg["idle_timeout_s"])
        while True:
            await asyncio.sleep(10)
            now = time.time()
            for cid, s in list(self.streams.items()):
                dead = s["proc"].returncode is not None
                if dead or (now - s["last"]) > idle:
                    await self._kill(cid, s)

    async def _kill(self, cid: str, s: dict) -> None:
        try:
            if s["proc"].returncode is None:
                s["proc"].terminate()
                try:
                    await asyncio.wait_for(s["proc"].wait(), timeout=3)
                except asyncio.TimeoutError:
                    s["proc"].kill()
        except Exception:
            pass
        shutil.rmtree(s["dir"], ignore_errors=True)
        self.streams.pop(cid, None)

    async def stop_all(self) -> None:
        for cid, s in list(self.streams.items()):
            await self._kill(cid, s)


CFG = load_config()
ST = Streamer(CFG)

app = FastAPI(title="secubox-freeboxtv", version="0.1.0", root_path="/api/v1/freeboxtv")
router = APIRouter()


@app.on_event("startup")
async def _startup():
    Path(CFG["hls_dir"]).mkdir(parents=True, exist_ok=True)
    await ST.refresh_channels()
    asyncio.create_task(ST.reaper())
    asyncio.create_task(_refresh_loop())


@app.on_event("shutdown")
async def _shutdown():
    await ST.stop_all()


async def _refresh_loop():
    while True:
        await asyncio.sleep(float(CFG["refresh_s"]))
        await ST.refresh_channels()


@router.get("/health")
async def health() -> dict:
    actifs = sum(1 for s in ST.streams.values() if s["proc"].returncode is None)
    return {"ok": True, "channels": len(ST.channels), "streams": actifs}


@router.get("/channels")
async def channels() -> dict:
    chs = sorted(ST.channels.values(), key=lambda c: c["lcn"])
    # On n'expose PAS l'URL RTSP interne : le client ne voit que l'id + le HLS.
    return {"channels": [{"id": c["id"], "lcn": c["lcn"], "name": c["name"],
                          "hls": f"/api/v1/freeboxtv/hls/{c['id']}/live.m3u8"} for c in chs]}


@router.get("/hls/{cid}/live.m3u8")
async def manifest(cid: str):
    if not cid.isdigit() or cid not in ST.channels:
        raise HTTPException(404, "chaîne inconnue")
    d = await ST.ensure(cid)
    if d is None:
        raise HTTPException(503, "trop de flux actifs — réessaie")
    if not await ST.wait_manifest(d):
        raise HTTPException(504, "flux indisponible (Freebox ?)")
    ST.touch(cid)
    return FileResponse(d / "live.m3u8", media_type="application/vnd.apple.mpegurl",
                        headers={"Cache-Control": "no-store"})


@router.get("/hls/{cid}/{seg}")
async def segment(cid: str, seg: str):
    if not cid.isdigit() or not _SEG_RE.match(seg) or ".." in seg:
        raise HTTPException(400, "requête invalide")
    f = (ST.hls_root / cid / seg)
    if not f.is_file():
        raise HTTPException(404, "segment absent")
    ST.touch(cid)
    mt = "application/vnd.apple.mpegurl" if seg.endswith(".m3u8") else "video/mp2t"
    return FileResponse(f, media_type=mt, headers={"Cache-Control": "no-store"})


app.include_router(router)
