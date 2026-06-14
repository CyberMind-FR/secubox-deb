# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# #570 — DPI media/content-type statistifier. Buckets every mitm response
# by content-type CATEGORY and by PROVIDER (eTLD+1), summing Content-Length
# (header only — never reads the body, safe on video/large media). Rolling
# in-memory counters flushed to /run/secubox/media.json for the donut UI.
from __future__ import annotations

import json
import os
import re
import time

from mitmproxy import http

_STATS = "/run/secubox/media.json"

# content-type → (category, emoji). Order matters (first match wins).
_CATS = (
    ("page", "\U0001F4C4", ("text/html", "application/xhtml")),       # 📄
    ("image", "\U0001F5BC", ("image/",)),                            # 🖼
    ("video", "\U0001F3AC", ("video/", "application/vnd.apple.mpegurl",
                              "application/x-mpegurl", "application/dash+xml")),  # 🎬
    ("audio", "\U0001F3B5", ("audio/",)),                            # 🎵
    ("script", "\U0001F9E9", ("javascript", "ecmascript")),          # 🧩
    ("style", "\U0001F3A8", ("text/css",)),                          # 🎨
    ("font", "\U0001F524", ("font/", "application/font", "application/vnd.ms-fontobject",
                             "application/x-font")),                  # 🔤
    ("api", "\U0001F4E6", ("application/json", "+json", "application/xml",
                            "text/xml", "application/grpc")),         # 📦
    ("text", "\U0001F4DD", ("text/plain", "text/")),                 # 📝
)
_OTHER = ("other", "❓")  # ❓
EMOJI = {c: e for c, e, _ in _CATS}
EMOJI[_OTHER[0]] = _OTHER[1]

_MAX_PROVIDERS = 250
_2L_TLD = ("co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.za", "gouv.fr")

_cats: dict = {}
_providers: dict = {}
_total = {"bytes": 0, "count": 0, "since": int(time.time())}
_last_flush = 0.0


def _category(ct: str) -> tuple:
    ct = (ct or "").split(";", 1)[0].strip().lower()
    if not ct:
        return _OTHER
    for cat, emoji, frags in _CATS:
        if any(f in ct for f in frags):
            return (cat, emoji)
    return _OTHER


def _registrable(host: str) -> str:
    host = (host or "").split(":", 1)[0].lower().strip(".")
    if not host or host.replace(".", "").isdigit():
        return host or "?"
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _2L_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def _flush(force: bool = False) -> None:
    global _last_flush
    now = time.time()
    if not force and (now - _last_flush) < 5:
        return
    _last_flush = now
    # cap providers to the heaviest _MAX_PROVIDERS by bytes
    global _providers
    if len(_providers) > _MAX_PROVIDERS:
        _providers = dict(sorted(_providers.items(),
                                 key=lambda kv: -kv[1]["bytes"])[:_MAX_PROVIDERS])
    try:
        os.makedirs(os.path.dirname(_STATS), exist_ok=True)
        with open(_STATS, "w", encoding="utf-8") as f:
            json.dump({"categories": _cats, "providers": _providers,
                       "total": _total, "updated": int(now)}, f)
    except Exception:
        pass


class MediaStats:
    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        h = flow.response.headers
        cat, _ = _category(h.get("content-type", ""))
        try:
            size = int(h.get("content-length", "0") or "0")
        except (TypeError, ValueError):
            size = 0
        prov = _registrable(flow.request.pretty_host or "")

        c = _cats.setdefault(cat, {"bytes": 0, "count": 0})
        c["bytes"] += size
        c["count"] += 1
        p = _providers.setdefault(prov, {"bytes": 0, "count": 0})
        p["bytes"] += size
        p["count"] += 1
        _total["bytes"] += size
        _total["count"] += 1
        _flush()


addons = [MediaStats()]
