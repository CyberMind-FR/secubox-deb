# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# #577 — shared media proxy-cache. One fetch serves every R2/R3 client:
# cacheable GET media/static (image / video segment / audio / font / css /
# js) is stored on disk, keyed by URL, and served from cache on subsequent
# requests from ANY client — saving upstream bandwidth + latency.
#
# Safety rails for the RAM-light cabine:
#   - DEFAULT OFF (filter `media_cache` toggle) ; instantly killable.
#   - per-object cap (16 MB) gated on Content-Length BEFORE buffering, so a
#     large/progressive video is passed through, never cached/RAM-held by us.
#   - 2 GB on-disk LRU budget, evicted oldest-first.
#   - never caches Range/partial, authenticated, Set-Cookie, no-store/private.
#   - fail-open everywhere : a cache error must never break the flow.
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time

from mitmproxy import http

try:
    if "/usr/lib/secubox/toolbox" not in sys.path:
        sys.path.insert(0, "/usr/lib/secubox/toolbox")
    from secubox_toolbox.filters import get_filters
except Exception:
    def get_filters(force: bool = False):
        return {"media_cache": False}

CACHE_DIR = "/var/cache/secubox/toolbox/media"
STATS = "/run/secubox/media_cache.json"
MAX_OBJ = 16 * 1024 * 1024          # 16 MB / object
MAX_TOTAL = 2 * 1024 * 1024 * 1024  # 2 GB on disk
DEFAULT_TTL = 3600                  # 1 h when upstream gives no max-age

_CACHEABLE = ("image/", "video/", "audio/", "font/", "text/css",
              "javascript", "ecmascript", "application/font",
              "application/vnd.ms-fontobject")
_MAXAGE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

# in-memory index (mitmproxy hooks run single-threaded in the event loop)
_index: dict = {}   # key -> {"size": int, "exp": float, "atime": float, "ct": str}
_total = 0
_stats = {"hits": 0, "misses": 0, "stored": 0, "evicted": 0,
          "bytes_served": 0, "since": int(time.time())}
_last_flush = 0.0


def _key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", "ignore")).hexdigest()


def _paths(key: str):
    d = os.path.join(CACHE_DIR, key[:2])
    return os.path.join(d, key), os.path.join(d, key + ".m")


def _enabled() -> bool:
    try:
        return bool(get_filters().get("media_cache"))
    except Exception:
        return False


def _cacheable_ct(ct: str) -> bool:
    ct = (ct or "").split(";", 1)[0].strip().lower()
    return bool(ct) and any(f in ct for f in _CACHEABLE)


def _flush_stats(force: bool = False) -> None:
    global _last_flush
    now = time.time()
    if not force and (now - _last_flush) < 5:
        return
    _last_flush = now
    try:
        os.makedirs(os.path.dirname(STATS), exist_ok=True)
        with open(STATS, "w", encoding="utf-8") as f:
            json.dump({**_stats, "objects": len(_index),
                       "bytes_cached": _total, "updated": int(now)}, f)
    except Exception:
        pass


def _load_index() -> None:
    """Rebuild the index from disk on startup (bounded, best-effort)."""
    global _total
    try:
        for sub in os.listdir(CACHE_DIR):
            d = os.path.join(CACHE_DIR, sub)
            if not os.path.isdir(d):
                continue
            for name in os.listdir(d):
                if name.endswith(".m"):
                    continue
                fp = os.path.join(d, name)
                try:
                    st = os.stat(fp)
                    meta = {}
                    mp = fp + ".m"
                    if os.path.exists(mp):
                        with open(mp, encoding="utf-8") as mf:
                            meta = json.load(mf)
                    _index[name] = {"size": st.st_size,
                                    "exp": meta.get("exp", 0),
                                    "atime": st.st_atime,
                                    "ct": meta.get("ct", "")}
                    _total += st.st_size
                except Exception:
                    pass
    except FileNotFoundError:
        pass


def _evict_if_needed() -> None:
    global _total
    if _total <= MAX_TOTAL:
        return
    # oldest atime first
    for key, e in sorted(_index.items(), key=lambda kv: kv[1]["atime"]):
        if _total <= MAX_TOTAL:
            break
        body, meta = _paths(key)
        try:
            os.remove(body)
        except OSError:
            pass
        try:
            os.remove(meta)
        except OSError:
            pass
        _total -= e["size"]
        _index.pop(key, None)
        _stats["evicted"] += 1


class MediaCache:
    def __init__(self):
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            _load_index()
        except Exception:
            pass

    # ── serve from cache (request hook) ──
    def request(self, flow: http.HTTPFlow) -> None:
        if not _enabled():
            return
        r = flow.request
        if r.method != "GET":
            return
        if "range" in r.headers or "authorization" in r.headers:
            return
        key = _key(r.pretty_url or "")
        e = _index.get(key)
        if not e:
            _stats["misses"] += 1
            return
        if e["exp"] and e["exp"] < time.time():
            return  # stale — let it revalidate/refetch (and re-store)
        body_path, _m = _paths(key)
        try:
            with open(body_path, "rb") as f:
                body = f.read()
        except OSError:
            _index.pop(key, None)
            return
        e["atime"] = time.time()
        try:
            os.utime(body_path, None)
        except OSError:
            pass
        _stats["hits"] += 1
        _stats["bytes_served"] += len(body)
        _flush_stats()
        flow.response = http.Response.make(
            200, body,
            {"Content-Type": e.get("ct") or "application/octet-stream",
             "X-SecuBox-Cache": "HIT",
             "Cache-Control": "public, max-age=300"},
        )

    # ── store to cache (response hook) ──
    def response(self, flow: http.HTTPFlow) -> None:
        global _total
        if not _enabled() or not flow.response:
            return
        r = flow.request
        resp = flow.response
        if r.method != "GET" or resp.status_code != 200:
            return
        if "range" in r.headers or "authorization" in r.headers:
            return
        if resp.headers.get("x-secubox-cache") == "HIT":
            return
        cc = (resp.headers.get("cache-control", "") or "").lower()
        if "no-store" in cc or "private" in cc:
            return
        if "set-cookie" in resp.headers:
            return
        if not _cacheable_ct(resp.headers.get("content-type", "")):
            return
        # size gate on the HEADER — never cache (nor force-buffer) > MAX_OBJ
        try:
            clen = int(resp.headers.get("content-length", "0") or "0")
        except (TypeError, ValueError):
            clen = 0
        if clen <= 0 or clen > MAX_OBJ:
            return
        try:
            body = resp.content or b""
        except Exception:
            return
        if not body or len(body) > MAX_OBJ:
            return
        # freshness window
        m = _MAXAGE.search(cc)
        ttl = int(m.group(1)) if m else DEFAULT_TTL
        if ttl <= 0:
            return
        key = _key(r.pretty_url or "")
        body_path, meta_path = _paths(key)
        try:
            os.makedirs(os.path.dirname(body_path), exist_ok=True)
            tmp = body_path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(body)
            os.replace(tmp, body_path)
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump({"ct": (resp.headers.get("content-type", "") or "").split(";")[0],
                           "exp": time.time() + ttl,
                           "url": (r.pretty_url or "")[:300]}, f)
        except Exception:
            return
        old = _index.get(key, {}).get("size", 0)
        _total += len(body) - old
        _index[key] = {"size": len(body), "exp": time.time() + ttl,
                       "atime": time.time(),
                       "ct": (resp.headers.get("content-type", "") or "").split(";")[0]}
        _stats["stored"] += 1
        _evict_if_needed()
        _flush_stats()


addons = [MediaCache()]
