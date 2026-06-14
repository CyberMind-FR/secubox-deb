# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# #566 — R3+/R4 silent ad/banner/widget GHOSTER + economisable savings.
#
# For R3+/R4 tunnel clients (on 10.99.1.0/24) ONLY, and only when enabled
# in the modular filter config (toolbox WebUI → filters.json):
#   - cosmetic ghost: inject a <style> that hides ad / consent-nag /
#     newsletter-popup / social-widget containers (1st-party page stays
#     usable) ;
#   - block: 204 known ad/tracker hosts to save real bandwidth.
# Tallies ghosted requests + estimated bytes saved → /run/secubox/ghost.json,
# which inject_banner surfaces as quick stats. Doctrine: opt-in (filter
# toggle), logged, reversible.
from __future__ import annotations

import json
import os
import re
import sys
import time

from mitmproxy import http

# Shared modular filter config (best-effort import; safe defaults if absent).
try:
    if "/usr/lib/secubox/toolbox" not in sys.path:
        sys.path.insert(0, "/usr/lib/secubox/toolbox")
    from secubox_toolbox.filters import get_filters
except Exception:
    def get_filters(force: bool = False):
        return {"ad_ghost": True, "ad_ghost_block": True,
                "ad_ghost_categories": {"ads": True, "consent_nag": True,
                                        "newsletter": True, "social_widgets": True}}

_STATS = "/run/secubox/ghost.json"
_EST_BYTES_PER_REQ = 45000  # honest estimate per blocked ad/tracker request

# Ad / tracker hosts to 204 (bandwidth save). Conservative: ad/tracker only.
_AD_HOST = re.compile(
    r"(?:^|\.)(?:doubleclick|googlesyndication|googleadservices|"
    r"googletagservices|adservice\.google|amazon-adsystem|adnxs|adsrvr|"
    r"adform|criteo|rubiconproject|taboola|outbrain|smartadserver|moatads|"
    r"scorecardresearch|2mdn|adroll|pubmatic|openx|casalemedia|"
    r"yieldlove|sharethrough|teads|3lift|adsystem|adserver)",
    re.IGNORECASE,
)

# Cosmetic hide selectors, grouped so the WebUI can toggle each category.
_COSMETIC = {
    "ads": (
        '[id^="google_ads"]', '[id^="div-gpt-ad"]', 'ins.adsbygoogle',
        'iframe[src*="doubleclick"]', 'iframe[src*="googlesyndication"]',
        'iframe[src*="amazon-adsystem"]', '[class*="ad-banner"]',
        '[class*="advert"]', '[id*="banner-ad"]', '[id*="ad-container"]',
        '[class*="-ads"]', '[class*="sponsored"]', 'aside[aria-label*="publicit"]',
    ),
    "consent_nag": (
        '#onetrust-banner-sdk', '#onetrust-consent-sdk', '#didomi-host',
        '.qc-cmp2-container', '[id^="sp_message_container"]',
        '[id*="cookie-consent"]', '[class*="cookie-banner"]',
        '[class*="cookie-notice"]', '[aria-label*="cookie"]', '.cmpbox',
    ),
    "newsletter": (
        '[class*="newsletter-popup"]', '[class*="signup-modal"]',
        '[id*="newsletter-modal"]', '[class*="subscribe-overlay"]',
    ),
    "social_widgets": (
        '.fb-like', '.twitter-share-button', '[class*="social-share"]',
        'iframe[src*="facebook.com/plugins"]', 'iframe[src*="platform.twitter"]',
    ),
}

_RE_HEAD = re.compile(rb"</head>", re.IGNORECASE)
_MARK = b"sbx-ghost-style"

_counts = {"blocked_requests": 0, "bytes_saved_est": 0, "pages_cleaned": 0,
           "since": int(time.time())}
_last_flush = 0.0


def _is_r3plus(flow) -> bool:
    try:
        ip = flow.client_conn.peername[0]
        return bool(ip) and ip.startswith("10.99.1.")
    except Exception:
        return False


def _flush(force: bool = False) -> None:
    global _last_flush
    now = time.time()
    if not force and (now - _last_flush) < 5:
        return
    _last_flush = now
    try:
        os.makedirs(os.path.dirname(_STATS), exist_ok=True)
        with open(_STATS, "w", encoding="utf-8") as f:
            json.dump({**_counts, "updated": int(now)}, f)
    except Exception:
        pass


def _style_for(cats: dict) -> bytes:
    sels = []
    for cat, on in cats.items():
        if on and cat in _COSMETIC:
            sels.extend(_COSMETIC[cat])
    if not sels:
        return b""
    rule = ",".join(sels) + "{display:none!important;visibility:hidden!important}"
    return (b"<style id=\"sbx-ghost-style\">" + rule.encode("utf-8") + b"</style>")


class AdGhost:
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        f = get_filters()
        if not (f.get("ad_ghost") and f.get("ad_ghost_block")):
            return
        if not _is_r3plus(flow):
            return
        host = flow.request.pretty_host or ""
        if _AD_HOST.search(host):
            flow.response = http.Response.make(
                204, b"", {"X-SecuBox-Ghost": "blocked"})
            _counts["blocked_requests"] += 1
            _counts["bytes_saved_est"] += _EST_BYTES_PER_REQ
            _flush()

    def response(self, flow: http.HTTPFlow) -> None:
        f = get_filters()
        if not f.get("ad_ghost") or not _is_r3plus(flow):
            return
        if not flow.response or flow.response.status_code != 200:
            return
        ct = (flow.response.headers.get("content-type", "") or "").lower()
        if "text/html" not in ct:
            return
        try:
            body = flow.response.content or b""
        except Exception:
            return
        if not body or _MARK in body:
            return
        style = _style_for(f.get("ad_ghost_categories", {}))
        if not style:
            return
        if _RE_HEAD.search(body):
            new = _RE_HEAD.sub(style + b"</head>", body, count=1)
        else:
            new = style + body
        flow.response.content = new
        _counts["pages_cleaned"] += 1
        _flush()


addons = [AdGhost()]
