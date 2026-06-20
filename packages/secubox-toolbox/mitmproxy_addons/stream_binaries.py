# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: toolbox :: stream large BINARY responses (#686)
#
# Replaces the content-agnostic `--set stream_large_bodies=1m`, which streamed
# EVERY body >1MB — including large HTML (leparisien.fr) — and streamed bodies
# can't be banner-injected → "plus de banner". Here we stream only large
# NON-HTML responses (APK / XPI / video / octet-stream / big downloads) so they
# pass through the HTTP/2 forging path VERBATIM (the buffer+reframe corrupted the
# 14MB APK over the R3 tunnel), while HTML is always buffered so inject_banner /
# ad_ghost still work.
from mitmproxy import http

_THRESHOLD = 1_000_000  # 1 MB
# Always-stream binary content-types regardless of declared length (covers
# chunked downloads with no Content-Length).
_BIN_CT = (
    "application/vnd.android.package-archive",  # .apk
    "application/x-xpinstall",                  # .xpi
    "application/octet-stream",
    "application/zip",
    "application/pdf",
    "video/",
    "audio/",
)


class StreamBinaries:
    def responseheaders(self, flow: http.HTTPFlow) -> None:
        try:
            r = flow.response
            if r is None:
                return
            ct = (r.headers.get("content-type", "") or "").lower()
            if "text/html" in ct:
                return  # NEVER stream HTML — banner + ad_ghost need the body
            if any(b in ct for b in _BIN_CT):
                r.stream = True
                return
            try:
                cl = int(r.headers.get("content-length", "0") or "0")
            except (TypeError, ValueError):
                cl = 0
            if cl >= _THRESHOLD:
                r.stream = True
        except Exception:
            pass


addons = [StreamBinaries()]
