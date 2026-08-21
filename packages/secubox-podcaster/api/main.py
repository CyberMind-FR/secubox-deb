# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Podcaster
CyberMind — https://cybermind.fr

Modern podcast manager: subscribe to feeds, download episodes locally, and
re-publish a shareable RSS. FastAPI on a Unix socket; SQLite store; an asyncio
download worker (background task, fire-and-forget queue). Feed parsing is pure
stdlib (xml.etree) to keep Debian deps minimal — only httpx is required.
"""
import asyncio
import html
import os
import re
import shutil
import tempfile
import time
import tomllib
import zipfile
from email.utils import parsedate_to_datetime, format_datetime
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

import httpx
from fastapi import FastAPI, APIRouter, BackgroundTasks, Depends, HTTPException, Request
from starlette.requests import ClientDisconnect
from fastapi.responses import Response, FileResponse, JSONResponse
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

from . import store
from . import importer

log = get_logger("podcaster")

CONFIG_FILE = Path("/etc/secubox/podcaster.toml")
DEFAULT_CONFIG = {
    "media_path": "/var/lib/secubox/podcaster/media",
    "max_parallel": 2,
    "refresh_minutes": 60,
    "public_base": "",          # e.g. https://podcast.gk2.secubox.in (exposure); empty → LAN/relative
    "share_title": "SecuBox Podcaster",
    "keep_per_feed": 0,         # 0 = unlimited
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        if CONFIG_FILE.exists():
            cfg.update(tomllib.loads(CONFIG_FILE.read_text()))
    except Exception as e:  # pragma: no cover - defensive
        log.error(f"config load failed: {e}")
    return cfg


CFG = load_config()
MEDIA = Path(CFG["media_path"])

app = FastAPI(title="secubox-podcaster", version="1.0.0", root_path="/api/v1/podcaster")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()

# ── download queue (in-process, persisted state in SQLite) ──────────
_queue: "asyncio.Queue[int]" = asyncio.Queue()
_worker_started = False
# Episodes with a live download task, keyed by id. Used to (a) dedup: never run
# two _download_one for the same episode (they share deterministic tmp/dest
# paths → file corruption); (b) let a manual restart cancel a wedged download.
_inflight: "dict[int, asyncio.Task]" = {}

# A stalled server must not hang a slot forever. connect/write are short;
# read is per-chunk (aiter_bytes), so a server that opens the socket then goes
# silent aborts with httpx.ReadTimeout instead of blocking the queue for ever.
_DL_TIMEOUT = httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=30.0)
# Auto-retry budget: total attempts per episode before it rests in 'error'.
_MAX_ATTEMPTS = 3
# Backoff (seconds) before re-queuing a failed attempt; index by attempt number.
_RETRY_BACKOFF = (10, 30, 60)


# ════════════════════════════════════════════════════════════════════
# Models
# ════════════════════════════════════════════════════════════════════
class FeedIn(BaseModel):
    url: str
    auto_dl: bool = True


class OPMLIn(BaseModel):
    opml: str


class ImportIn(BaseModel):
    url: str
    mirror_peertube: bool = True
    create_billets: bool = True


class ConfigIn(BaseModel):
    media_path: Optional[str] = None
    max_parallel: Optional[int] = None
    refresh_minutes: Optional[int] = None
    public_base: Optional[str] = None
    share_title: Optional[str] = None
    keep_per_feed: Optional[int] = None


# ════════════════════════════════════════════════════════════════════
# Feed parsing (stdlib)
# ════════════════════════════════════════════════════════════════════
_NS = {"itunes": "http://www.itunes.com/dtds/podcast-1.0.dtd",
       "atom": "http://www.w3.org/2005/Atom"}


def _ts(s: Optional[str]) -> int:
    if not s:
        return 0
    try:
        return int(parsedate_to_datetime(s).timestamp())
    except Exception:
        return 0


def parse_feed(xml_bytes: bytes) -> tuple[dict, list[dict]]:
    """Return (feed_meta, [episode, ...]) from RSS 2.0 bytes."""
    root = ET.fromstring(xml_bytes)
    chan = root.find("channel")
    if chan is None:  # not RSS we understand
        return {}, []

    def t(el, tag):
        x = el.find(tag)
        return x.text.strip() if x is not None and x.text else None

    img = None
    ic = chan.find("itunes:image", _NS)
    if ic is not None:
        img = ic.get("href")
    if not img:
        im = chan.find("image/url")
        img = im.text.strip() if im is not None and im.text else None

    meta = {
        "title": t(chan, "title"),
        "description": t(chan, "description"),
        "site": t(chan, "link"),
        "image": img,
    }

    episodes = []
    for it in chan.findall("item"):
        enc = it.find("enclosure")
        if enc is None or not enc.get("url"):
            continue
        guid = t(it, "guid") or enc.get("url")
        dur = it.find("itunes:duration", _NS)
        episodes.append({
            "guid": guid,
            "title": t(it, "title"),
            "description": t(it, "description"),
            "pubdate": _ts(t(it, "pubDate")),
            "enclosure": enc.get("url"),
            "mime": enc.get("type") or "audio/mpeg",
            "bytes": int(enc.get("length") or 0),
            "duration": dur.text.strip() if dur is not None and dur.text else None,
        })
    return meta, episodes


async def _resolve_apple_podcast(url: str, cli: httpx.AsyncClient) -> str:
    """Apple Podcasts links wrap a real RSS feed. If `url` is an Apple/iTunes
    podcast link, look up its numeric id via the iTunes Lookup API and return the
    underlying `feedUrl`; otherwise return `url` unchanged (best-effort)."""
    m = re.search(r"(?:podcasts|itunes)\.apple\.com/.*?/id(\d+)", url)
    if not m:
        return url
    try:
        r = await cli.get(f"https://itunes.apple.com/lookup?id={m.group(1)}&entity=podcast",
                          headers={"User-Agent": "SecuBox-Podcaster/1.0"})
        r.raise_for_status()
        for res in r.json().get("results", []):
            if res.get("feedUrl"):
                log.info(f"resolved Apple Podcasts id {m.group(1)} -> {res['feedUrl']}")
                return res["feedUrl"]
    except Exception as e:  # noqa: BLE001 — fall back to the original url
        log.warning(f"apple podcast resolve failed for {url}: {e}")
    return url


async def fetch_and_store(url: str, auto_dl: Optional[bool] = None) -> dict:
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as cli:
        url = await _resolve_apple_podcast(url, cli)
        r = await cli.get(url, headers={"User-Agent": "SecuBox-Podcaster/1.0"})
        r.raise_for_status()
        meta, eps = parse_feed(r.content)
    fid = store.add_feed(url, meta, auto_dl=1 if auto_dl else 0)
    store.update_feed_meta(fid, meta)
    if auto_dl is not None:  # explicit add/toggle; None = refresh (keep current)
        store.set_feed_autodl(fid, 1 if auto_dl else 0)
    for ep in eps:
        store.upsert_episode(fid, ep)
    queued = await _autoqueue(fid)
    return {"feed_id": fid, "title": meta.get("title"),
            "episodes": len(eps), "queued": queued}


async def _autoqueue(fid: int) -> int:
    """If a feed has auto_dl, enqueue its not-yet-downloaded episodes (newest
    first, capped by keep_per_feed to avoid unbounded disk use)."""
    if not store.feed_autodl(fid):
        return 0
    cap = int(CFG.get("keep_per_feed", 0) or 0)
    n = 0
    for ep_id in store.pending_episode_ids(fid, cap):
        store.set_episode(ep_id, state="queued", progress=0, error=None)
        await _queue.put(ep_id)
        n += 1
    return n


# ════════════════════════════════════════════════════════════════════
# Download worker
# ════════════════════════════════════════════════════════════════════
def _safe_name(s: str, ext: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "episode"))[:80].strip("_")
    return f"{base or 'episode'}{ext}"


async def _download_one(ep_id: int) -> None:
    ep = store.get_episode(ep_id)
    if not ep or not ep.get("enclosure"):
        return
    store.set_episode(ep_id, state="downloading", progress=0, error=None)
    ext = os.path.splitext(ep["enclosure"].split("?")[0])[1][:5] or ".mp3"
    fdir = MEDIA / str(ep["feed_id"])
    fdir.mkdir(parents=True, exist_ok=True)
    dest = fdir / _safe_name(f"{ep_id}_{ep.get('title','')}", ext)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=_DL_TIMEOUT) as cli:
            async with cli.stream("GET", ep["enclosure"],
                                  headers={"User-Agent": "SecuBox-Podcaster/1.0"}) as r:
                r.raise_for_status()
                total = int(r.headers.get("content-length") or ep.get("bytes") or 0)
                got = 0
                with open(tmp, "wb") as fh:
                    async for chunk in r.aiter_bytes(65536):
                        fh.write(chunk)
                        got += len(chunk)
                        if total:
                            store.set_episode(ep_id, progress=min(99, got * 100 // total))
        tmp.rename(dest)
        store.set_episode(ep_id, state="done", progress=100, error=None, attempts=0,
                          local_path=str(dest), bytes=dest.stat().st_size)
        log.info(f"downloaded ep {ep_id} -> {dest}")
    except asyncio.CancelledError:
        # Manual restart cancelled us; drop the partial file and let the
        # re-queue (done by the caller) start a fresh attempt. Do NOT count
        # this as a failed attempt.
        tmp.unlink(missing_ok=True)
        raise
    except Exception as e:
        tmp.unlink(missing_ok=True)
        attempts = store.bump_attempts(ep_id)
        if attempts < _MAX_ATTEMPTS:
            delay = _RETRY_BACKOFF[min(attempts, len(_RETRY_BACKOFF)) - 1]
            store.set_episode(ep_id, state="queued", progress=0,
                              error=f"retry {attempts}/{_MAX_ATTEMPTS}: {str(e)[:150]}")
            log.warning(f"download ep {ep_id} failed (try {attempts}), "
                        f"re-queue in {delay}s: {e}")
            asyncio.create_task(_requeue_later(ep_id, delay))
        else:
            store.set_episode(ep_id, state="error",
                              error=f"gave up after {attempts} tries: {str(e)[:170]}")
            log.error(f"download ep {ep_id} failed permanently after {attempts}: {e}")


async def _requeue_later(ep_id: int, delay: float) -> None:
    """Sleep then push the episode back onto the download queue (bounded retry)."""
    await asyncio.sleep(delay)
    await _queue.put(ep_id)


async def _worker() -> None:
    sem = asyncio.Semaphore(max(1, int(CFG.get("max_parallel", 2))))

    async def run(ep_id):
        async with sem:
            await _download_one(ep_id)

    while True:
        ep_id = await _queue.get()
        cur = _inflight.get(ep_id)
        if cur is not None and not cur.done():
            continue  # dedup: an identical download is already running
        t = asyncio.create_task(run(ep_id))
        _inflight[ep_id] = t
        # Drop from the registry once finished, but only if we're still the
        # registered task (a later restart may have replaced us).
        t.add_done_callback(
            lambda done, e=ep_id: _inflight.get(e) is done and _inflight.pop(e, None))


async def _refresher() -> None:
    while True:
        await asyncio.sleep(max(5, int(CFG.get("refresh_minutes", 60))) * 60)
        for fid, url in store.all_feed_urls():
            # Les flux SYNTHETIQUES ne sont pas des sources HTTP.
            #
            # `youtube:<serie>` et `audiobook:<titre>` sont des conteneurs
            # crees localement (importeur yt-dlp, endpoint d'ajout) pour
            # regrouper des episodes. Les passer a un client HTTP produit, a
            # chaque cycle :
            #
            #   Request URL is missing an 'http://' or 'https://' protocol
            #
            # Quatre des cinq flux de cette board sont dans ce cas : le
            # rafraichisseur tournait, mais echouait sur tout sauf le seul vrai
            # RSS. Plus rien n'a ete telecharge depuis le 2026-07-25.
            if not url.startswith(("http://", "https://")):
                await _refresh_synthetic(fid, url)
                continue
            try:
                await fetch_and_store(url)
            except Exception as e:
                log.error(f"refresh feed {fid} failed: {e}")


async def _refresh_synthetic(fid: int, url: str) -> None:
    """Rafraichit un flux synthetique en relançant son import d'origine.

    Ne fait rien si l'URL source n'est pas connue : un flux importe avant que
    `site` ne soit enregistre n'a plus de trace de son origine, et il n'y a
    rien a re-interroger. On le dit UNE FOIS, en info, plutot que d'echouer en
    boucle a chaque cycle."""
    if not url.startswith("youtube:"):
        return                      # audiobook: n'a pas de source a re-lire
    src = store.feed_site(fid)
    if not src or not src.startswith(("http://", "https://")):
        log.info(f"feed {fid} ({url}): pas d'URL source enregistree, "
                 "rafraichissement impossible — reimportez-le une fois")
        return
    if importer.JOB.get("running"):
        return                      # un seul import a la fois
    try:
        # Signature complete : run_import(url, media_dir, mirror_peertube,
        # create_billets). Un appel a trois arguments passe la revue de code
        # et le controle syntaxique, puis echoue en TypeError au premier
        # cycle — c'est-a-dire une heure apres le deploiement, quand plus
        # personne ne regarde.
        await asyncio.to_thread(importer.run_import, src, str(MEDIA), False, False)
    except Exception as e:
        log.error(f"reimport feed {fid} ({src}) failed: {e}")


def _ensure_worker() -> None:
    """Lazy-start background tasks (sub-app lifespans don't fire under the aggregator)."""
    global _worker_started
    if _worker_started:
        return
    _worker_started = True
    store.init()
    MEDIA.mkdir(parents=True, exist_ok=True)
    # Recover downloads orphaned by a previous run: episodes left in
    # downloading/queued are reset to queued and re-fed to the in-memory queue.
    stuck = store.requeue_stuck()
    for ep_id in stuck:
        _queue.put_nowait(ep_id)
    if stuck:
        log.info(f"requeued {len(stuck)} orphaned download(s) on start")
    asyncio.create_task(_worker())
    asyncio.create_task(_refresher())


@app.on_event("startup")
async def _startup():
    _ensure_worker()


# ════════════════════════════════════════════════════════════════════
# Public endpoints (status / health / share)
# ════════════════════════════════════════════════════════════════════
@app.get("/health")
async def health():
    return {"status": "ok", "module": "deb"}


@router.get("/status")
async def status():
    _ensure_worker()
    return {
        "service": "active",
        "worker": _worker_started,
        "media_path": str(MEDIA),
        "public_base": CFG.get("public_base", ""),
        **store.counts(),
    }


def _xml_esc(s: Optional[str]) -> str:
    return html.escape(s or "", quote=True)


@router.get("/share/feed.xml")
async def share_feed(request: Request):
    """A generated RSS of the locally downloaded episodes (the relay/share feed)."""
    _ensure_worker()
    base = (CFG.get("public_base") or "").rstrip("/")
    if not base:
        base = str(request.base_url).rstrip("/")
    eps = store.downloaded_episodes()
    items = []
    for e in eps:
        url = f"{base}/api/v1/podcaster/media/{e['id']}"
        pub = format_datetime(datetime.fromtimestamp(e["pubdate"] or time.time(),
                                                     tz=timezone.utc))
        items.append(
            f"<item><title>{_xml_esc(e.get('title'))}</title>"
            f"<description>{_xml_esc(e.get('description'))}</description>"
            f"<pubDate>{pub}</pubDate>"
            f"<guid isPermaLink=\"false\">sbx-{e['id']}</guid>"
            f"<enclosure url=\"{_xml_esc(url)}\" type=\"{_xml_esc(e.get('mime') or 'audio/mpeg')}\" "
            f"length=\"{e.get('bytes') or 0}\"/></item>"
        )
    title = _xml_esc(CFG.get("share_title", "SecuBox Podcaster"))
    rss = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rss version="2.0"><channel>'
        f"<title>{title}</title><link>{_xml_esc(base)}</link>"
        f"<description>Locally relayed by SecuBox Podcaster</description>"
        + "".join(items) + "</channel></rss>"
    )
    return Response(content=rss, media_type="application/rss+xml")


@router.get("/public/library")
async def public_library():
    """Public listener library — downloaded/shared episodes only (no auth).
    Feeds the external portal frontend; exposes nothing un-shared."""
    _ensure_worker()
    eps = store.downloaded_episodes()
    feeds: dict = {}
    for e in eps:
        k = e.get("feed_title") or "Podcast"
        feeds[k] = feeds.get(k, 0) + 1
    return {
        "title": CFG.get("share_title", "SecuBox Podcaster"),
        "episodes": [{
            "id": e["id"], "title": e.get("title"), "feed": e.get("feed_title"),
            "feed_id": e.get("feed_id"),
            "pubdate": e.get("pubdate"), "duration": e.get("duration"),
            "mime": e.get("mime"), "bytes": e.get("bytes"),
            "media": f"/api/v1/podcaster/media/{e['id']}",
        } for e in eps],
        "feeds": feeds,
        "share": "/api/v1/podcaster/share/feed.xml",
    }


@router.get("/public/feed/{fid}/zip")
async def public_feed_zip(fid: int, background: BackgroundTasks):
    """Public: download all downloaded episodes of a feed as one ZIP.
    mp3/audio are already compressed → STORED (no recompress). Built to a temp
    file then streamed; cleaned up after send."""
    _ensure_worker()
    eps = [e for e in store.downloaded_episodes(limit=2000)
           if e.get("feed_id") == fid and e.get("local_path")
           and Path(e["local_path"]).exists()]
    if not eps:
        raise HTTPException(404, "no downloaded episodes for this feed")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", (eps[0].get("feed_title") or f"feed{fid}"))[:60] or f"feed{fid}"
    tmp = Path(tempfile.mkstemp(suffix=".zip", dir="/var/lib/secubox/podcaster")[1])
    eps.sort(key=lambda e: e.get("pubdate") or 0)
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_STORED) as z:
        for i, e in enumerate(eps):
            p = Path(e["local_path"])
            z.write(p, arcname=_safe_name(f"{i+1:03d}_{e.get('title') or p.stem}", p.suffix))
    background.add_task(lambda: tmp.unlink(missing_ok=True))
    return FileResponse(tmp, media_type="application/zip", filename=f"{name}.zip",
                        background=background)


@router.get("/media/{ep_id}")
async def media(ep_id: int):
    ep = store.get_episode(ep_id)
    if not ep or ep.get("state") != "done" or not ep.get("local_path"):
        raise HTTPException(404, "not downloaded")
    p = Path(ep["local_path"])
    if not p.exists():
        raise HTTPException(404, "file missing")
    # inline so browsers play it in <audio> (iOS Safari refuses 'attachment');
    # the portal/admin "download" links force a save via the HTML5 download attr.
    return FileResponse(p, media_type=ep.get("mime") or "audio/mpeg",
                        filename=p.name, content_disposition_type="inline")


@router.get("/feeds/{fid}/cover")
async def feed_cover(fid: int):
    """Public: the feed's artwork extracted from its media (audiobooks). Podcasts
    keep their RSS image URL; this only serves locally-extracted covers."""
    p = MEDIA / str(fid) / "cover.jpg"
    if not p.exists():
        raise HTTPException(404, "no cover")
    return FileResponse(p, media_type="image/jpeg",
                        headers={"Cache-Control": "public, max-age=86400"})


# ════════════════════════════════════════════════════════════════════
# Authenticated endpoints (manage)
# ════════════════════════════════════════════════════════════════════
@router.get("/feeds", dependencies=[Depends(require_jwt)])
async def feeds():
    _ensure_worker()
    return {"feeds": store.list_feeds()}


@router.post("/feeds", dependencies=[Depends(require_jwt)])
async def add_feed(body: FeedIn):
    _ensure_worker()
    url = body.url.strip()
    # Une URL YouTube n'est PAS un flux RSS : la parser en XML échoue
    # (« mismatched tag », #1101). On la route vers l'importeur yt-dlp, qui
    # télécharge la playlist/vidéo comme épisodes de podcast (mêmes cookies que
    # ytsas, #1100). Un import à la fois — 409 si un autre tourne.
    if importer.is_youtube_url(url):
        if importer.JOB.get("running"):
            raise HTTPException(409, "un import est déjà en cours")
        asyncio.create_task(asyncio.to_thread(
            importer.run_import, url, str(MEDIA), False, False))
        return {"ok": True, "imported": True, "started": url}
    try:
        return await fetch_and_store(url, auto_dl=body.auto_dl)
    except Exception as e:
        raise HTTPException(400, f"feed add failed: {e}")


@router.post("/feeds/{fid}/autodl", dependencies=[Depends(require_jwt)])
async def toggle_autodl(fid: int, on: bool = True):
    """Toggle auto-download for a feed. Turning it on also queues any episodes
    not yet downloaded (so the portal/share feed sync immediately)."""
    _ensure_worker()
    store.set_feed_autodl(fid, 1 if on else 0)
    queued = await _autoqueue(fid) if on else 0
    return {"ok": True, "auto_dl": on, "queued": queued}


@router.delete("/feeds/{fid}", dependencies=[Depends(require_jwt)])
async def del_feed(fid: int):
    store.delete_feed(fid)
    return {"ok": True}


@router.post("/feeds/import-opml", dependencies=[Depends(require_jwt)])
async def import_opml(body: OPMLIn):
    _ensure_worker()
    try:
        root = ET.fromstring(body.opml)
    except Exception as e:
        raise HTTPException(400, f"bad OPML: {e}")
    urls = [o.get("xmlUrl") for o in root.iter("outline") if o.get("xmlUrl")]
    added = 0
    for u in urls:
        try:
            await fetch_and_store(u)
            added += 1
        except Exception as e:
            log.error(f"opml feed {u}: {e}")
    return {"added": added, "total": len(urls)}


@router.post("/import/url", dependencies=[Depends(require_jwt)])
async def import_url(body: ImportIn):
    """Start a background import of a yt-dlp URL (video/playlist/site) into a
    podcaster feed, optionally mirroring each video to PeerTube and creating a
    billet per item. One import at a time; poll /import/status for progress."""
    _ensure_worker()
    if importer.JOB.get("running"):
        raise HTTPException(409, "an import is already running")
    url = body.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(400, "URL must start with http(s)://")
    # kick the blocking pipeline onto a worker thread so the loop stays free
    asyncio.create_task(asyncio.to_thread(
        importer.run_import, url, str(MEDIA),
        body.mirror_peertube, body.create_billets))
    return {"ok": True, "started": url}


@router.get("/import/status", dependencies=[Depends(require_jwt)])
async def import_status():
    return importer.JOB


_AUDIO_EXT = {".mp3", ".m4a", ".m4b", ".aac", ".ogg", ".opus", ".flac", ".wav", ".mp4"}
_AUDIO_MIME = {".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".m4b": "audio/mp4",
               ".aac": "audio/aac", ".ogg": "audio/ogg", ".opus": "audio/opus",
               ".flac": "audio/flac", ".wav": "audio/wav", ".mp4": "audio/mp4"}


@router.post("/audiobook/upload", dependencies=[Depends(require_jwt)])
async def audiobook_upload(request: Request, title: str = "Audiobook"):
    """Stream an uploaded ZIP to a temp file, extract its audio tracks, and
    publish them as a self-contained (synthetic) feed — already 'done' so they
    show in the library + share feed. Raw body (no python-multipart dep)."""
    _ensure_worker()
    title = (title or "Audiobook").strip() or "Audiobook"
    # Stage the upload on the SAME filesystem as the media store (media_path),
    # not a hardcoded eMMC path: the temp ZIP + the extracted tracks must live
    # where there's room (e.g. the SSD), and same-FS keeps the writes local.
    MEDIA.mkdir(parents=True, exist_ok=True)
    # Reject an upload we physically cannot store BEFORE streaming it: extraction
    # needs room for the temp ZIP *plus* the extracted tracks (~2x the ZIP), so a
    # large upload on a near-full store could only fail mid-write (a confusing
    # 500/502). Give an instant, clear 413 instead.
    clen = request.headers.get("content-length")
    if clen and clen.isdigit():
        need = int(clen) * 2 + (200 << 20)          # zip + extracted + 200MB margin
        free = shutil.disk_usage(MEDIA).free
        if need > free:
            raise HTTPException(
                413,
                f"not enough disk space: this upload needs ~{int(clen) * 2 >> 20} MB "
                f"(ZIP + extracted tracks) but only {free >> 20} MB is free on the "
                f"media store. Upload smaller per-book ZIPs, or point media_path "
                f"at larger storage.")
    tmp = Path(tempfile.mkstemp(suffix=".zip", dir=MEDIA)[1])
    try:
        try:
            with open(tmp, "wb") as fh:
                async for chunk in request.stream():
                    fh.write(chunk)
        except ClientDisconnect:
            # Upload aborted / a proxy in front cut the body: no partial feed to
            # clean up yet (extraction hasn't run), just report it cleanly.
            raise HTTPException(400, "upload interrupted before completion")
        # Extraction (zip walk + copy of possibly hundreds of MB) is blocking;
        # run it OFF the single-worker event loop so a large audiobook cannot
        # freeze the service (and delay the response past the proxy read
        # timeout, which was surfacing as a 502).
        return await asyncio.to_thread(_publish_audiobook_zip, tmp, title)
    finally:
        tmp.unlink(missing_ok=True)


def _extract_cover(audio_path: Path, dest: Path) -> bool:
    """Pull embedded cover art (ID3 APIC / MP4 'covr' / FLAC picture) from an
    audio file, downscale it, and write it to `dest` as JPEG. Returns True on
    success, False if there's no art or anything goes wrong (best-effort)."""
    try:
        import io
        from mutagen import File as MutagenFile
        mf = MutagenFile(str(audio_path))
        if mf is None:
            return False
        data = None
        tags = getattr(mf, "tags", None)
        if tags:
            for k in list(tags.keys()):
                if k.startswith("APIC"):                 # ID3 (mp3)
                    data = tags[k].data
                    break
            if data is None and "covr" in tags:          # MP4 (m4a/m4b)
                covr = tags["covr"]
                if covr:
                    data = bytes(covr[0])
        if data is None and getattr(mf, "pictures", None):  # FLAC / Ogg
            data = mf.pictures[0].data
        if not data:
            return False
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert("RGB")
        img.thumbnail((600, 600))
        dest.parent.mkdir(parents=True, exist_ok=True)
        img.save(dest, "JPEG", quality=85)
        return True
    except Exception:  # noqa: BLE001 — cover art is optional, never break upload
        return False


def _publish_audiobook_zip(tmp: Path, title: str) -> dict:
    """Blocking: validate the ZIP, create a synthetic feed and extract its audio
    tracks as already-'done' episodes. On ANY failure the partial feed is
    removed so a broken upload never leaves an orphaned feed behind."""
    if not zipfile.is_zipfile(tmp):
        raise HTTPException(400, "not a valid ZIP")
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "audiobook"
    fid = store.add_feed(f"audiobook:{slug}:{int(time.time())}",
                         {"title": title, "description": f"Audiobook: {title}"})
    try:
        fdir = MEDIA / str(fid)
        fdir.mkdir(parents=True, exist_ok=True)
        tracks = 0
        with zipfile.ZipFile(tmp) as z:
            names = [n for n in z.namelist()
                     if os.path.splitext(n)[1].lower() in _AUDIO_EXT
                     and not n.endswith("/")]
            names.sort()  # chapter order
            base = int(time.time())
            first_dest: Optional[Path] = None
            for i, n in enumerate(names):
                ext = os.path.splitext(n)[1].lower()
                tname = _safe_name(f"{i+1:03d}_{os.path.basename(n)}", ext)
                dest = fdir / tname
                if first_dest is None:
                    first_dest = dest
                with z.open(n) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out, 1024 * 256)
                store.upsert_episode(fid, {
                    "guid": f"ab:{fid}:{i}", "title": f"{i+1:02d} · {os.path.splitext(os.path.basename(n))[0]}",
                    "description": title, "pubdate": base + i,
                    "enclosure": f"local:{dest}", "mime": _AUDIO_MIME.get(ext, "audio/mpeg"),
                    "bytes": dest.stat().st_size,
                })
                # mark immediately downloaded (local file already present)
                ep = store.list_episodes(feed_id=fid)
                for e in ep:
                    if e["guid"] == f"ab:{fid}:{i}":
                        store.set_episode(e["id"], state="done", progress=100,
                                          local_path=str(dest))
                        break
                tracks += 1
        if not tracks:
            store.delete_feed(fid)
            raise HTTPException(400, "no audio files found in ZIP")
        # Extract the embedded cover (ID3 APIC / MP4 covr / FLAC picture) from the
        # first track → the feed's artwork, served at /feeds/<fid>/cover.
        if first_dest and _extract_cover(first_dest, fdir / "cover.jpg"):
            store.update_feed_meta(fid, {"image": f"/api/v1/podcaster/feeds/{fid}/cover"})
        log.info(f"audiobook '{title}' -> feed {fid}, {tracks} tracks")
        return {"title": title, "feed_id": fid, "tracks": tracks}
    except HTTPException:
        raise
    except Exception:
        store.delete_feed(fid)  # never leave a half-extracted feed behind
        raise


@router.get("/episodes", dependencies=[Depends(require_jwt)])
async def episodes(feed_id: Optional[int] = None, state: Optional[str] = None):
    _ensure_worker()
    return {"episodes": store.list_episodes(feed_id, state)}


@router.post("/episodes/{ep_id}/download", dependencies=[Depends(require_jwt)])
async def download(ep_id: int):
    _ensure_worker()
    ep = store.get_episode(ep_id)
    if not ep:
        raise HTTPException(404, "no such episode")
    # Cancel any live download for this episode first, and wait for it to
    # unwind, so the fresh re-queue can never race the old task (which would
    # otherwise be deduped away or collide on the temp file).
    cur = _inflight.get(ep_id)
    if cur is not None and not cur.done():
        cur.cancel()
        # Wait for the cancelled task to unwind WITHOUT re-raising its
        # CancelledError/exception here (asyncio.wait swallows the awaitee's
        # outcome but still propagates cancellation of *this* handler).
        await asyncio.wait({cur})
    # Manual (re)download resets the auto-retry budget so a wedged/failed
    # episode gets a fresh set of tries.
    store.set_episode(ep_id, state="queued", progress=0, error=None, attempts=0)
    await _queue.put(ep_id)
    return {"ok": True, "queued": ep_id}


@router.get("/downloads", dependencies=[Depends(require_jwt)])
async def downloads():
    _ensure_worker()
    return {"downloads": store.list_episodes(state="downloading")
            + store.list_episodes(state="queued")}


@router.get("/config", dependencies=[Depends(require_jwt)])
async def get_config():
    return {"config": load_config()}


@router.post("/config", dependencies=[Depends(require_jwt)])
async def set_config(body: ConfigIn):
    cfg = load_config()
    for k, v in body.model_dump(exclude_none=True).items():
        cfg[k] = v
    lines = []
    for k, v in cfg.items():
        if isinstance(v, str):
            lines.append(f'{k} = "{v}"')
        elif isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        else:
            lines.append(f"{k} = {v}")
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text("\n".join(lines) + "\n")
    except Exception as e:
        raise HTTPException(500, f"write failed: {e}")
    return {"ok": True, "config": cfg, "note": "restart secubox-podcaster to apply"}


app.include_router(router)
