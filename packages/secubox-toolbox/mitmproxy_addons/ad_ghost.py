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

import concurrent.futures
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

# #656 — contextual ad metrics + candidate learning. SQLite is touched ONLY
# off the request hot path, on a single bg worker (mirrors local_store.py).
try:
    from secubox_toolbox import store as _store      # noqa: E402
except Exception:  # pragma: no cover
    _store = None

# #659 — resolve client IP → stable per-visitor identity hash (best-effort).
try:
    from _common import mac_hash_of            # noqa: E402
except Exception:  # pragma: no cover
    mac_hash_of = None

_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="sbx_ad")

_STATS = "/run/secubox/ghost.json"
_EST_BYTES_PER_REQ = 45000  # honest estimate per blocked ad/tracker request

# #656 — operator allowlist (host or registrable, one per line, # comments).
# Allowlist ALWAYS wins: an allowlisted host is never 204'd nor recorded.
_ALLOW_PATH = "/var/lib/secubox/toolbox/ad-allowlist.txt"
# #658 — the appliance's OWN domains. NEVER blocked/learned (the aggressive
# learner once self-promoted secubox.in → 204'd all *.secubox.in for R3).
# Hard-coded (env-overridable) so it survives a reflash with no allowlist file.
_SELF_REGS = {d.strip().lower() for d in
              os.environ.get("SECUBOX_SELF_DOMAINS", "secubox.in").split(",")
              if d.strip()}
# Path heuristics for 3rd-party ad/track candidate capture (learning only).
_AD_PATH = re.compile(r"/ads?/|/adserver|/pagead|/gampad|/doubleclick|/beacon|"
                      r"/pixel|/collect|/track(ing)?|/telemetry|/metric", re.I)

# Hot-path dict increments only; drained + offloaded to SQLite in _flush.
_ctx: dict = {}        # (host, site, action) -> [hits, bytes]
_cand: dict = {}       # (host, site) -> hits
_cli: dict = {}        # #659 (mac_hash, ad_host) -> [hits, bytes]
_allow: set = set()
_allow_mtime = 0.0

# Ad / tracker hosts to 204 (bandwidth save). Conservative: ad/tracker only.
_AD_HOST = re.compile(
    r"(?:^|\.)(?:doubleclick|googlesyndication|googleadservices|"
    r"googletagservices|adservice\.google|amazon-adsystem|adnxs|adsrvr|"
    r"adform|criteo|rubiconproject|taboola|outbrain|smartadserver|moatads|"
    r"scorecardresearch|2mdn|adroll|pubmatic|openx|casalemedia|"
    r"yieldlove|sharethrough|teads|3lift|adsystem|adserver)",
    re.IGNORECASE,
)

# #589 — auto-learned bad hosts (threat-intel + classified cross-site
# trackers), rebuilt hourly by secubox-toolbox-autolearn. Loaded with a
# mtime check so a fresh learn takes effect within ~60 s, no restart.
_LEARNED_PATH = "/var/lib/secubox/toolbox/learned-trackers.txt"
_learned: set = set()
_learned_mtime = 0.0
_learned_check = 0.0
_2L_TLD = ("co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.za", "gouv.fr")


def _registrable(host: str):
    host = (host or "").split(":")[0].lower().strip(".")
    if not host or host.replace(".", "").isdigit() or ":" in host:
        return None
    p = host.split(".")
    if len(p) <= 2:
        return host
    last2 = ".".join(p[-2:])
    return ".".join(p[-3:]) if (last2 in _2L_TLD and len(p) >= 3) else last2


def _allowed(host: str) -> bool:
    """#656 — allowlist wins. True if host (or its registrable) is allowed."""
    global _allow, _allow_mtime
    try:
        m = os.stat(_ALLOW_PATH).st_mtime if os.path.exists(_ALLOW_PATH) else 0.0
        if m != _allow_mtime:
            _allow = set()
            if m:
                with open(_ALLOW_PATH, encoding="utf-8") as f:
                    for ln in f:
                        ln = ln.split("#", 1)[0].strip().lower()
                        if ln:
                            _allow.add(ln)
            _allow_mtime = m
    except Exception:
        pass
    h = (host or "").lower()
    reg = _registrable(h) or h
    # #658 — own infra always allowed (never block/capture our own domains),
    # independent of the allowlist file (reflash-safe).
    if reg in _SELF_REGS or any(h == d or h.endswith("." + d) for d in _SELF_REGS):
        return True
    return h in _allow or reg in _allow


def _site_of(flow) -> str:
    """Registrable domain of the page that issued this request (Referer)."""
    try:
        ref = flow.request.headers.get("referer", "") or ""
        if ref:
            from urllib.parse import urlparse
            return _registrable(urlparse(ref).hostname or "") or ""
    except Exception:
        pass
    return ""


def _learned_set() -> set:
    global _learned, _learned_mtime, _learned_check
    now = time.time()
    if now - _learned_check < 60:
        return _learned
    _learned_check = now
    try:
        m = os.path.getmtime(_LEARNED_PATH)
        if m != _learned_mtime:
            with open(_LEARNED_PATH, encoding="utf-8") as f:
                _learned = {ln.strip().lower() for ln in f if ln.strip()}
            _learned_mtime = m
    except Exception:
        pass
    return _learned

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
    # #656 — drain the hot-path dicts and offload the SQLite writes to the bg
    # thread, so the proxy event loop never touches the DB. Snapshot+clear
    # under no lock is fine: CPython dict ops are atomic and a missed increment
    # between snapshot and clear is harmless (stats, not security).
    if _store is not None and (_ctx or _cand or _cli):
        try:
            rows = [(h, s, a, v[0], v[1]) for (h, s, a), v in _ctx.items()]
            cand_rows = [(h, s, n) for (h, s), n in _cand.items()]
            cli_rows = [(mh, h, v[0], v[1]) for (mh, h), v in _cli.items()]
            _ctx.clear()
            _cand.clear()
            _cli.clear()
            if rows:
                _executor.submit(_store.record_ad_blocks, rows)
            if cand_rows:
                _executor.submit(_store.record_ad_candidates, cand_rows)
            if cli_rows:
                _executor.submit(_store.record_ad_client_blocks, cli_rows)
        except Exception:
            pass


# EasyList cosmetic rules compiled by the modular filter resource (#740).
# Element-hide is the MITM layer's unique value (DNS can't hide DOM nodes); the
# DNS sinkhole already drops the network requests, so here we only inject CSS.
_FL_COSMETIC_PATH = "/var/lib/secubox/filterlists/cosmetic.json"
_FL_GLOBAL_CAP = 3000  # cap generic (##) selectors so injected CSS stays sane
_fl_cosmetic_cache = {"mtime": -1.0, "data": {}, "global": []}


def _fl_cosmetic() -> dict:
    """Cached load of cosmetic.json (mtime-guarded, like the learned set)."""
    try:
        m = os.path.getmtime(_FL_COSMETIC_PATH)
    except OSError:
        return _fl_cosmetic_cache
    if m != _fl_cosmetic_cache["mtime"]:
        try:
            with open(_FL_COSMETIC_PATH, encoding="utf-8") as fh:
                data = json.load(fh)
            _fl_cosmetic_cache["data"] = data if isinstance(data, dict) else {}
            _fl_cosmetic_cache["global"] = (_fl_cosmetic_cache["data"].get("*") or [])[:_FL_GLOBAL_CAP]
            _fl_cosmetic_cache["mtime"] = m
        except Exception:
            pass
    return _fl_cosmetic_cache


def _fl_selectors_for(host: str) -> list:
    """Per-domain EasyList element-hide selectors for `host` (host + parents)."""
    fl = _fl_cosmetic()
    data = fl["data"]
    if not data:
        return []
    out = list(fl["global"])
    h = (host or "").lower().strip(".")
    # Walk host → registrable so both `www.x.com` and `x.com` rules apply.
    seen = set()
    parts = h.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in seen:
            continue
        seen.add(cand)
        sub = data.get(cand)
        if sub:
            out.extend(sub)
    return out


def _style_for(cats: dict, host: str = "") -> bytes:
    sels = []
    for cat, on in cats.items():
        if on and cat in _COSMETIC:
            sels.extend(_COSMETIC[cat])
    # #740 — fold in EasyList cosmetic (generic capped + per-domain targeted).
    if cats.get("ads", True):
        sels.extend(_fl_selectors_for(host))
    if not sels:
        return b""
    # Dedup while preserving order; bound the rule size.
    seen = set()
    uniq = []
    for s in sels:
        if s and s not in seen:
            seen.add(s)
            uniq.append(s)
    sel = ",".join(uniq)
    # #584 — NO placeholder : collapse the ghosted ad slot entirely so the
    # space disappears (display:none), rather than leaving a void/black-hole.
    # Host-blocking (204) still saves the bandwidth ; this just hides the box.
    rule = sel + "{display:none!important;visibility:hidden!important;}"
    return (b"<style id=\"sbx-ghost-style\">" + rule.encode("utf-8") + b"</style>")


class AdGhost:
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        f = get_filters()
        if not (f.get("ad_ghost") and f.get("ad_ghost_block")):
            return
        if not _is_r3plus(flow):
            return
        host = flow.request.pretty_host or ""
        # #656 — allowlist ALWAYS wins: never block, never record.
        if _allowed(host):
            return
        blocked = bool(_AD_HOST.search(host))
        learned = False
        if not blocked and f.get("autolearn", True):
            reg = _registrable(host)
            if reg and (reg in _learned_set() or host.lower() in _learned_set()):
                blocked = learned = True
        site = _site_of(flow)
        if blocked:
            flow.response = http.Response.make(
                204, b"", {"X-SecuBox-Ghost": "learned" if learned else "blocked"})
            _counts["blocked_requests"] += 1
            if learned:
                _counts["learned_blocks"] = _counts.get("learned_blocks", 0) + 1
            _counts["bytes_saved_est"] += _EST_BYTES_PER_REQ
            # #656 — contextual block tally (per host/site), dict increment only.
            try:
                if len(_ctx) < 20000:
                    k = (host, site, "block")
                    v = _ctx.get(k) or [0, 0]
                    v[0] += 1
                    v[1] += _EST_BYTES_PER_REQ
                    _ctx[k] = v
            except Exception:
                pass
            # #659 — per-visitor breakdown: resolve the client identity and
            # tally this blocked ad host against it. Dict increment only.
            try:
                if mac_hash_of is not None and len(_cli) < 50000:
                    ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
                    mh = mac_hash_of(ip) if ip else None
                    if mh:
                        ck = (mh, host)
                        cv = _cli.get(ck) or [0, 0]
                        cv[0] += 1
                        cv[1] += _EST_BYTES_PER_REQ
                        _cli[ck] = cv
            except Exception:
                pass
            _flush()
        elif f.get("ad_learn", True) and site:
            # #656 — aggressive candidate capture: 3rd-party request whose path
            # smells like an ad/track endpoint. Learning only; no block here.
            try:
                if (_registrable(host) != _registrable(site)
                        and _AD_PATH.search(flow.request.path or "")
                        and len(_cand) < 20000):
                    ck = (host, site)
                    _cand[ck] = _cand.get(ck, 0) + 1
            except Exception:
                pass

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
        # #656 — silent (cosmetic-hide) tally per site, dict increment only.
        try:
            if len(_ctx) < 20000:
                site = _site_of(flow) or (flow.request.pretty_host or "")
                k = (site, site, "silent")
                v = _ctx.get(k) or [0, 0]
                v[0] += 1
                _ctx[k] = v
        except Exception:
            pass
        _flush()


addons = [AdGhost()]
