# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-ytsas
CyberMind — https://cybermind.fr

FastAPI control API for the YouTube / web-media SAS gateway. Sibling of the
torrent SAS (same downstream: kept-by-default library, opt-in ephemeral TTL,
disk-floor purge, host-mediated conserve — video to PeerTube, audio to
Lyrion, issue #967) with yt-dlp as the fetch engine and a cookie vault for
gated content.

Runs INSIDE the ytsas LXC on 0.0.0.0:8091 (auth is enforced upstream by the
nginx gate / sbxwaf, as with the torrent SAS in-LXC app). Never blocks the
event loop: yt-dlp is an async subprocess and blocking handlers are plain
`def` (FastAPI runs them in a threadpool).
"""

import json
import os
import shutil
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from engine import AuthRequired, EngineError, Engine
from library import Library

# --------------------------------------------------------------------- config
DOWNLOAD_DIR = os.environ.get("YTSAS_DOWNLOAD_DIR", "/data/ytsas")
DB_PATH = os.environ.get("YTSAS_DB", os.path.join(DOWNLOAD_DIR, "library.db"))
COOKIE_PATH = os.environ.get("YTSAS_COOKIES", "/var/lib/secubox/ytsas/cookies.txt")
WWW_DIR = os.environ.get("YTSAS_WWW", "/opt/secubox-ytsas/www")
MAX_ACTIVE = int(os.environ.get("YTSAS_MAX_ACTIVE", "2"))
PORT = int(os.environ.get("YTSAS_PORT", "8091"))
DISK_FLOOR = float(os.environ.get("YTSAS_DISK_FLOOR_GB", "5")) * 1e9
# Cookies older than this are flagged "stale" in /cookies/status (advisory).
COOKIE_STALE_SECS = int(os.environ.get("YTSAS_COOKIE_STALE_DAYS", "30")) * 86400

# Conserve: the LXC drops a request on the shared /data volume, a HOST timer
# (secubox-ytsas-conserve) classifies the file and routes it — PeerTube for
# video, Lyrion for audio (issue #967) — with the creds/LXC-access it holds,
# then drops a result the LXC folds back in on /list. Same split as the
# torrent SAS — creds stay host-side.
CONSERVE_QUEUE = os.path.join(DOWNLOAD_DIR, ".conserve-queue")
CONSERVE_RESULTS = os.path.join(DOWNLOAD_DIR, ".conserve-results")

_MIME = {
    "mp4": "video/mp4", "m4v": "video/mp4", "webm": "video/webm",
    "mkv": "video/x-matroska", "mov": "video/quicktime", "avi": "video/x-msvideo",
    "flv": "video/x-flv", "ts": "video/mp2t",
    "mp3": "audio/mpeg", "m4a": "audio/mp4", "ogg": "audio/ogg",
    "flac": "audio/flac", "wav": "audio/wav",
}

os.makedirs(DOWNLOAD_DIR, exist_ok=True)
library = Library(DB_PATH)
engine = Engine(DOWNLOAD_DIR, library, COOKIE_PATH, max_active=MAX_ACTIVE)

app = FastAPI(title="secubox-ytsas")

API = "/api/v1/ytsas"


# --------------------------------------------------------------------- helpers
def disk_free_bytes() -> int:
    """Free bytes on /data (the real disk-floor signal), else 'infinite'."""
    try:
        st = os.statvfs(DOWNLOAD_DIR)
        return st.f_bavail * st.f_frsize
    except OSError:
        return 1 << 62


def _mime_of(name: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return _MIME.get(ext, "application/octet-stream")


async def _read_body(request: Request) -> dict:
    """Tolerate an empty / non-JSON body: return {} instead of 400."""
    try:
        raw = await request.body()
    except Exception:
        return {}
    if not raw or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"value": data}
    except (ValueError, TypeError):
        # A bare string body (e.g. a pasted URL) — expose it under "value".
        return {"value": raw.decode("utf-8", "replace").strip()}


def _drain_conserve_results():
    """Fold any host-written conserve results into the library (called on
    /list). A result's shape says which partner handled it: {"url": ...} came
    from PeerTube, {"library_path": ...} came from Lyrion (see
    secubox-ytsas-conserve) — each goes to its own column pair so a Lyrion
    result never gets misread as a stalled/failed PeerTube upload (or vice
    versa)."""
    try:
        files = [f for f in os.listdir(CONSERVE_RESULTS) if f.endswith(".json")]
    except OSError:
        return
    for f in files:
        vid = f[:-5]
        p = os.path.join(CONSERVE_RESULTS, f)
        try:
            r = json.loads(open(p, "r", encoding="utf-8").read())
            if "library_path" in r:
                library.set_lyrion(vid, r.get("status") or "done", r.get("library_path"))
            else:
                library.set_peertube(vid, r.get("status") or "done", r.get("url"))
        except (OSError, ValueError):
            pass
        try:
            os.unlink(p)
        except OSError:
            pass


def _item_file(row) -> str:
    """Resolve the on-disk video file for a row (path may be a dir or a file)."""
    path = row.get("path") if row else None
    if not path:
        return None
    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        return Engine._pick_file(path)
    return None


# ---------------------------------------------------------------------- routes
@app.get(API + "/health")
async def health():
    return {"status": "ok", "module": "ytsas"}


@app.post(API + "/add")
async def add(request: Request):
    """Queue a yt-dlp job. Tolerant input: url/link/magnet/value or bare string.

    400 only if empty. A gated failure returns a clear status (auth requise /
    cookies périmés), never a raw yt-dlp traceback.
    """
    b = await _read_body(request)
    url = (b.get("url") or b.get("link") or b.get("magnet")
           or b.get("value") or "").strip()
    if not url:
        return JSONResponse({"error": "url required"}, status_code=400)
    try:
        return await engine.add(url)
    except AuthRequired as e:
        return JSONResponse({"error": str(e), "auth_required": True}, status_code=401)
    except EngineError as e:
        return JSONResponse({"error": str(e)}, status_code=502)


@app.get(API + "/list")
def list_items():
    """Library rows enriched with live job progress; drains conserve results."""
    _drain_conserve_results()
    out = []
    for r in library.list():
        job = engine.job(r["id"])
        r = dict(r)
        if job:
            r["progress"] = job.get("progress", 0.0)
            r["job_status"] = job.get("status")
            r["job_error"] = job.get("error")
        else:
            r["progress"] = 100.0 if r.get("complete") else 0.0
            r["job_status"] = "complete" if r.get("complete") else "idle"
            r["job_error"] = None
        out.append(r)
    return out


@app.get(API + "/files/{id}")
def files(id: str):
    row = library.get(id)
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    f = _item_file(row)
    if not f:
        return {"files": []}
    try:
        length = os.path.getsize(f)
    except OSError:
        length = 0
    return {"files": [{"idx": 0, "name": os.path.basename(f), "length": length}]}


@app.get(API + "/stream/{id}")
def stream(id: str, request: Request):
    """HTTP Range streaming of the downloaded file. 206/416/404 (mirror stream.js)."""
    row = library.get(id)
    if not row:
        return Response("not found", status_code=404)
    f = _item_file(row)
    if not f or not os.path.isfile(f):
        return Response("not found", status_code=404)
    try:
        total = os.path.getsize(f)
    except OSError:
        return Response("not found", status_code=404)
    ctype = _mime_of(f)
    rng = request.headers.get("range")

    if not rng:
        def full():
            with open(f, "rb") as fh:
                while True:
                    chunk = fh.read(262144)
                    if not chunk:
                        break
                    yield chunk
        return StreamingResponse(
            full(), status_code=200, media_type=ctype,
            headers={"Content-Length": str(total), "Accept-Ranges": "bytes"})

    # bytes=start-end
    start, end = 0, total - 1
    try:
        spec = rng.split("=", 1)[1]
        s, _, e = spec.partition("-")
        if s.strip():
            start = int(s)
        if e.strip():
            end = int(e)
    except (ValueError, IndexError):
        start, end = 0, total - 1
    if end >= total:
        end = total - 1
    if start >= total or start > end:
        return Response(status_code=416,
                        headers={"Content-Range": f"bytes */{total}"})

    length = end - start + 1

    def ranged():
        remaining = length
        with open(f, "rb") as fh:
            fh.seek(start)
            while remaining > 0:
                chunk = fh.read(min(262144, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    return StreamingResponse(
        ranged(), status_code=206, media_type=ctype,
        headers={
            "Content-Range": f"bytes {start}-{end}/{total}",
            "Content-Length": str(length),
            "Accept-Ranges": "bytes",
        })


@app.post(API + "/keep/{id}")
async def keep(id: str):
    if not library.get(id):
        return JSONResponse({"error": "not found"}, status_code=404)
    library.keep(id)
    return {"status": "kept"}


@app.post(API + "/ephemeral/{id}")
async def ephemeral(id: str, request: Request):
    """Opt-in purge: {seconds} or {until}. Falsy/absent = cancel (conserve)."""
    if not library.get(id):
        return JSONResponse({"error": "not found"}, status_code=404)
    b = await _read_body(request)
    until = b.get("until")
    if until is None:
        try:
            secs = float(b.get("seconds"))
        except (TypeError, ValueError):
            secs = 0
        if secs and secs > 0:
            until = int(time.time()) + int(secs)
    else:
        try:
            until = int(until)
        except (TypeError, ValueError):
            until = 0
    if not until or int(until) <= int(time.time()):
        library.keep(id)
        return {"status": "conserved"}
    library.set_ephemeral(id, int(until))
    return {"status": "ephemeral", "ephemeral_until": int(until)}


@app.post(API + "/conserve/{id}")
async def conserve(id: str):
    """Drop a conserve request for the HOST processor, which classifies the
    file and routes it to PeerTube (video) or Lyrion (audio). The
    set_peertube(id, "queued", None) call below is a destination-agnostic
    "in flight" marker — the real partner isn't known until the host
    classifies the file; the panel just shows a generic pending state
    either way, and _drain_conserve_results() records the actual
    destination once the host writes a result."""
    row = library.get(id)
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    if not row.get("complete"):
        return JSONResponse({"error": "download not complete"}, status_code=409)
    f = _item_file(row)
    if not f or not os.path.isfile(f):
        return JSONResponse({"error": "file not ready"}, status_code=409)
    try:
        os.makedirs(CONSERVE_QUEUE, exist_ok=True)
        with open(os.path.join(CONSERVE_QUEUE, id + ".json"), "w",
                  encoding="utf-8") as fh:
            json.dump({
                "id": id,
                "url": row.get("url"),
                "title": row.get("title") or id,
                "name": row.get("title") or id,
                "file": f,
            }, fh)
    except OSError as e:
        return JSONResponse({"error": "queue write failed: " + str(e)},
                            status_code=500)
    library.set_peertube(id, "queued", None)
    return {"status": "queued", "file": os.path.basename(f)}


@app.post(API + "/remove/{id}")
async def remove(id: str):
    row = library.get(id)
    if row and row.get("path"):
        p = row["path"]
        try:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            elif os.path.isfile(p):
                # path is a file → remove its containing per-id dir if ours.
                d = os.path.dirname(p)
                if os.path.basename(d) == id:
                    shutil.rmtree(d, ignore_errors=True)
                else:
                    os.unlink(p)
        except OSError:
            pass
    engine.jobs.pop(id, None)
    library.remove(id)
    return {"status": "removed"}


@app.get(API + "/status")
async def status():
    return {
        "status": "ok",
        "active": engine.active(),
        "disk_free": disk_free_bytes(),
        "jobs": len(engine.jobs),
        "cookies": engine._has_cookies(),
        **library.counts(),
    }


@app.post(API + "/cookies")
async def upload_cookies(request: Request):
    """Store a Netscape cookies.txt to the vault, 0600. NEVER logged."""
    raw = await request.body()
    # Accept either a raw text body or a JSON {cookies|value: "..."} envelope.
    text = None
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                text = data.get("cookies") or data.get("value")
        except (ValueError, TypeError):
            text = raw.decode("utf-8", "replace")
    if not text or not text.strip():
        return JSONResponse({"error": "cookies body required"}, status_code=400)
    try:
        os.makedirs(os.path.dirname(COOKIE_PATH), exist_ok=True)
        # Write 0600 atomically (never widen the vault).
        fd = os.open(COOKIE_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, text.encode("utf-8", "replace"))
        finally:
            os.close(fd)
        os.chmod(COOKIE_PATH, 0o600)
    except OSError as e:
        # Do NOT echo the cookie content; only the errno-level reason.
        return JSONResponse({"error": "vault write failed: " + e.strerror},
                            status_code=500)
    engine.cookies_stale = False
    return {"status": "stored"}


@app.get(API + "/cookies/status")
async def cookies_status():
    present = engine._has_cookies()
    mtime = None
    stale = engine.cookies_stale
    if present:
        try:
            mtime = int(os.path.getmtime(COOKIE_PATH))
            if (int(time.time()) - mtime) > COOKIE_STALE_SECS:
                stale = True
        except OSError:
            pass
    return {"present": present, "mtime": mtime, "stale": bool(stale)}


# ----------------------------------------------------------------- purge loop
def _run_purge():
    """Reap expired ephemerals + disk-floor safety valve. NEVER touch conserved."""
    now = int(time.time())
    victims = set(library.expired_ephemeral(now))
    if disk_free_bytes() < DISK_FLOOR:
        # Disk-floor safety valve: reclaim EVERY user-marked-ephemeral item,
        # even before its time — never conserved (kept) content.
        victims |= set(library.marked_ephemeral())
    for vid in victims:
        row = library.get(vid)
        if row and row.get("path"):
            p = row["path"]
            try:
                if os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    d = os.path.join(DOWNLOAD_DIR, vid)
                    shutil.rmtree(d, ignore_errors=True)
            except OSError:
                pass
        engine.jobs.pop(vid, None)
        library.remove(vid)
    return victims


@app.on_event("startup")
async def _startup():
    import asyncio

    async def purge_loop():
        while True:
            try:
                await asyncio.to_thread(_run_purge)
            except Exception:
                pass
            await asyncio.sleep(300)

    asyncio.create_task(purge_loop())


# Serve the webui static from the app root, AFTER the API routes so /api/v1/...
# is matched first (StaticFiles at "/" otherwise catches everything). Guarded so
# a missing www dir doesn't crash the app in dev.
if os.path.isdir(WWW_DIR):
    app.mount("/", StaticFiles(directory=WWW_DIR, html=True), name="www")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
