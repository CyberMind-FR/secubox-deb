# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""mitmproxy addon :: inject MITM transparency banner into HTML responses.

CSPN R2 requirement (CM-WALL-EGRESS-2026-06 §3) : transparency obligatoire.
The user being inspected MUST see at all times that R2 inspection is active +
be able to verify the CA fingerprint against their device trust store.

Phase 3 (#492) : the banner is now data-rich per-site (status + quality grade
+ country flag + ASN + app emoji from secubox_core.classifiers), with CSP-
aware fallback : strict-CSP sites get a JS-less HTML+style pill, lax sites
get the interactive version.

Skip non-HTML and non-200 responses. Idempotent (won't double-inject).
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from mitmproxy import http

log = logging.getLogger("secubox.toolbox.banner")

CA_PEM = Path("/etc/secubox/toolbox/ca/ca.pem")
PORTAL_URL_CAPTIVE = "http://10.99.0.1:8088"
REPORT_URL_CAPTIVE = "http://10.99.0.1:8088/report/me/html"
# Phase 6 (#496) : remote (R3 WG) clients can't reach the captive 10.99.0.1.
# Use the public kbin vhost (HAProxy → backend toolbox_landing → 10.99.0.1).
PORTAL_URL_PUBLIC = "https://kbin.gk2.secubox.in"
REPORT_URL_PUBLIC = "https://kbin.gk2.secubox.in/report/me/html"
WG_PEERS_DB = Path("/var/lib/secubox/toolbox/wg-peers.json")

_RE_BODY_CLOSE = re.compile(rb"</body\s*>", re.I)
_GUARD = b"__GONDWANA_MITM_BANNER__"


def _ncr(s: str) -> str:
    """Encode any non-ASCII char as HTML numeric character reference.

    Why: pages with non-UTF-8 declared charset (legacy iso-8859-1) reinterpret
    our injected raw UTF-8 emoji bytes as garbage. NCRs (&#xXXXX;) are
    charset-agnostic — the browser decodes them after charset translation.

    Use for HTML content (both CSP-strict HTML body and JS innerHTML).
    """
    out = []
    for ch in s:
        cp = ord(ch)
        if cp < 0x80:
            out.append(ch)
        else:
            out.append(f"&#x{cp:X};")
    return "".join(out)

# Phase 3 classifiers (soft import : ToolBoX runs even if not deployed)
# Phase 6.L (#496) : host_app classifier actually lives in
# secubox_toolbox.dpi_class (the secubox_core.classifiers.host_app module
# was an aspirational reference that never shipped). Fallback chain tries
# the aspirational location first for forward compat, then dpi_class.
_HAS_CLASSIFIERS = False
_host_app = None
_sec_quality = None
_whitelist_mod = None
try:
    import sys as _sys
    if "/usr/lib/secubox/toolbox" not in _sys.path:
        _sys.path.insert(0, "/usr/lib/secubox/toolbox")
    try:
        from secubox_core.classifiers import host_app as _host_app
    except ImportError:
        from secubox_toolbox import dpi_class as _host_app  # 100+ patterns
    try:
        from secubox_core.classifiers import security_quality as _sec_quality
    except ImportError:
        pass
    try:
        from secubox_core import whitelist as _whitelist_mod
    except ImportError:
        pass
    _HAS_CLASSIFIERS = _host_app is not None
except Exception:
    pass

# Geo lookup (toolbox-local, falls back gracefully)
try:
    import sys as _sys
    _sys.path.insert(0, "/usr/lib/secubox/toolbox")
    from secubox_toolbox import geo as _geo_mod  # type: ignore
    _HAS_GEO = True
except Exception:
    _HAS_GEO = False


def _ca_sha1() -> str:
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(CA_PEM), "-noout", "-fingerprint", "-sha1"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout
        if "=" in out:
            return out.split("=", 1)[1].strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "?"


_CA_SHA1 = _ca_sha1()


# ── Phase 6 (#496) : WG peer → stable anon hash ─────────────────────
import hashlib as _hashlib
import json as _jsonmod


def _peer_hash_from_ip(ip: str | None) -> str | None:
    """Map 10.99.1.X (WG peer ip) → sha256(peer_pubkey)[:16].

    Stable per-device, anonymous, used as mac_hash equivalent for R3
    clients (who don't have an ARP-resolvable MAC on the captive subnet).
    """
    if not ip or not ip.startswith("10.99.1."):
        return None
    try:
        if not WG_PEERS_DB.exists():
            return None
        peers = _jsonmod.loads(WG_PEERS_DB.read_text()).get("peers", {})
        for pubkey, meta in peers.items():
            if meta.get("ip") == ip:
                return _hashlib.sha256(pubkey.encode()).hexdigest()[:16]
    except Exception:
        pass
    return None


def _report_url_for(flow) -> str:
    """Dynamic report URL :
    - captive R2 client → http://10.99.0.1:8088/report/me/html (local)
    - WG R3 client → https://kbin.gk2.secubox.in/report/me/html?mh=<wg_hash>
      (reachable from anywhere, anonymized, no captive subnet required)
    """
    try:
        ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        wgh = _peer_hash_from_ip(ip)
        if wgh:
            return f"{REPORT_URL_PUBLIC}?mh={wgh}"
    except Exception:
        pass
    return REPORT_URL_CAPTIVE


def _level_label(flow) -> str:
    """'R2' for captive clients, 'R3' for WG tunnel clients."""
    try:
        ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        if ip and ip.startswith("10.99.1."):
            return "R3"
    except Exception:
        pass
    return "R2"


# ── Phase 6.G (#496) : cookie + tracker detection ──────────────────
# Tracker patterns mirror secubox-ad-guard ad_patterns — single source of
# truth would be _whitelist_mod / a new classifiers module, but for the
# banner we keep them inline (no extra import, no network calls).
_TRACKER_PATTERNS = re.compile(
    r"(?:^|\.)(?:"
    r"doubleclick|googlesyndication|googleadservices|googletagmanager|"
    r"google-analytics|googletagservices|"
    r"facebook\.com/tr|connect\.facebook\.net|facebook\.net|"
    r"scorecardresearch|chartbeat|hotjar|mixpanel|amplitude|"
    r"segment\.com|segment\.io|criteo|adnxs|rubiconproject|"
    r"taboola|outbrain|smartadserver|optimizely|fullstory|"
    r"newrelic|datadog|sentry|amazon-adsystem|adsrvr|"
    r"yieldlove|moatads|adservice\.google|adsystem|adserver"
    r")",
    re.IGNORECASE,
)
# 1st-party host classification : is the page ITSELF on a tracker domain ?
_TRACKER_HOST_PATTERNS = re.compile(
    r"^(?:ads?\d*|adserv|adtrack|doubleclick|googleadservices|"
    r"googlesyndication|pixel|tracking|telemetry|analytics|"
    r"beacon|metric|stats?\d*)\.",
    re.IGNORECASE,
)


def _count_cookies(flow: http.HTTPFlow) -> tuple[int, int]:
    """Returns (set_cookie_count, sent_cookie_count) for this flow."""
    try:
        sc = flow.response.headers.get_all("set-cookie") or []
        rc_raw = flow.request.headers.get_all("cookie") or []
        sent = 0
        for h in rc_raw:
            sent += sum(1 for p in h.split(";") if "=" in p)
        return (len(sc), sent)
    except Exception:
        return (0, 0)


def _count_trackers_in_body(body: bytes, cap: int = 200_000) -> int:
    """Count unique tracker domains referenced in the HTML body. Capped to
    cap bytes to avoid CPU spike on large pages. Returns 0 on any error."""
    try:
        if not body or len(body) == 0:
            return 0
        slice_ = body[:cap]
        try:
            text = slice_.decode("utf-8", errors="ignore")
        except Exception:
            text = slice_.decode("latin-1", errors="ignore")
        matches = set(_TRACKER_PATTERNS.findall(text.lower()))
        return len(matches)
    except Exception:
        return 0


# Phase 10 (#501 perf) — per-host context cache.
#
# `_compute_site_context` used to call into 4 sub-systems per response :
# `_host_app.classify_host` (host → emoji + app via 100+ pattern walk),
# `_whitelist_mod.match`, `_geo_mod.lookup` (DNS + GeoIP mmdb lookup),
# plus the body tracker scan + cookie counts. Of those, ALL host-keyed
# results are stable for hours — there's no point recomputing per
# response. An LRU cache on `host` shaves ~20-50 ms per HTML response,
# and frees the GIL during banner injection so the rest of the addon
# chain (and other workers) can progress.
import functools as _functools


@_functools.lru_cache(maxsize=2048)
def _host_signals(host: str) -> tuple:
    """Return (app_emoji, app, flag, country, asn, status, status_icon).

    Tuple form keeps the cache key + value flat and hashable. We don't
    cache cookie counts (per-flow) or tracker scan (per-response) — only
    the truly host-stable values.

    A cache miss is the expensive path : classify_host (~50 µs typical,
    up to 5 ms on the hot patterns), whitelist match (~1 µs), and the
    GeoIP lookup (DNS + mmdb — can be 5-50 ms on a cold DNS cache).
    """
    app_emoji = "❔"
    app = host
    flag = ""
    country = ""
    asn = ""
    status = "inspected"
    status_icon = "🔍"

    if not _HAS_CLASSIFIERS:
        return (app_emoji, app, flag, country, asn, status, status_icon)

    try:
        cls = _host_app.classify_host(host)
        app_emoji = cls.get("emoji", "❔")
        app = cls.get("app", host) if cls.get("app") != "?" else host
    except Exception:
        pass

    try:
        wl = _whitelist_mod.match(host)
        if wl:
            status = "bypassed-whitelist"
            status_icon = "🛡"
        elif re.search(r"\.(signal|whispersystems|threema|simplex|matrix|proton|tutanota)\.", host):
            status = "e2e-opaque"
            status_icon = "🔐"
    except Exception:
        pass

    if _HAS_GEO:
        try:
            info = _geo_mod.lookup(host) or {}
            flag = info.get("flag", "")
            country = info.get("country_iso", "")
            asn = (info.get("asn_org") or "")[:24]
        except Exception:
            pass

    return (app_emoji, app, flag, country, asn, status, status_icon)


def _compute_site_context(flow: http.HTTPFlow) -> dict:
    """Compute per-site signals for the dynamic right-side of the banner.

    Phase 10 (#501 perf) — host-stable signals come from the LRU cache
    (`_host_signals`). The body tracker scan is REMOVED ; the
    1st-party `is_tracker_host` flag already surfaces tracker hosts as
    `⚠ tracker-host` in the banner, which is the privacy-relevant
    signal. Counting trackers in the body required a full body buffer
    scan that delayed banner injection by 30-200 ms per HTML response
    on big publishers — not worth it for a "trackers: N" count that
    most users don't read.
    """
    host = (flow.request.host or "").lower()
    ctx = {
        "host": host[:50],
        "app_emoji": "❔",
        "app": host,
        "grade": "?",
        "grade_color": "#888",
        "flag": "",
        "country": "",
        "asn": "",
        "status": "inspected",
        "status_icon": "🔍",
        "cookies_set": 0,
        "cookies_sent": 0,
        "trackers": 0,
        "is_tracker_host": False,
        "utiq_recent_count": 0,
        "tor_mode": False,
    }

    # #683 — kbin Tor egress status. When armed, this flow's upstream exits via
    # Tor (only the exit IP changes; inspection is still happening — that's how
    # this banner exists). Surfaced as a 🧅 chip so the client sees they're
    # anonymised. get_filters is 5 s-cached → cheap on the hot path.
    try:
        from secubox_toolbox.filters import get_filters as _gf
        ctx["tor_mode"] = bool(_gf().get("tor_mode", False))
    except Exception:
        pass

    # Host-stable signals — single LRU lookup per host.
    (ctx["app_emoji"], ctx["app"], ctx["flag"], ctx["country"], ctx["asn"],
     ctx["status"], ctx["status_icon"]) = _host_signals(host)

    # Cookies (cheap : just header counts, name-less for privacy)
    set_n, sent_n = _count_cookies(flow)
    ctx["cookies_set"] = set_n
    ctx["cookies_sent"] = sent_n

    # Phase 8 (#500) — Utiq tile : count events from this peer in the
    # last hour.  Best-effort : if the store import fails or the DB
    # isn't reachable we just leave the counter at 0 and the tile
    # disappears.  No exception ever propagates to the addon chain.
    try:
        from secubox_toolbox import utiq as _u
        peer_ip = None
        if flow.client_conn and flow.client_conn.peername:
            peer_ip = flow.client_conn.peername[0]
        if peer_ip:
            ctx["utiq_recent_count"] = _u.client_recent_count(peer_ip, hours=1)
    except Exception:
        pass

    # Trackers : 1st-party host flag only — body scan removed in Phase 10
    # for perceived-latency win. The banner still shows ⚠ tracker-host
    # when the visited site is itself a known tracker domain.
    ctx["is_tracker_host"] = bool(_TRACKER_HOST_PATTERNS.match(host))

    # Quality grade (passive — we only see response headers + transport)
    try:
        # Detect TLS version from connection metadata if available
        tls_v = None
        if hasattr(flow, "server_conn") and hasattr(flow.server_conn, "tls_version"):
            v = flow.server_conn.tls_version or ""
            if "1.3" in v or "13" in v:
                tls_v = "13"
            elif "1.2" in v or "12" in v:
                tls_v = "12"
        is_e2e = ctx["status"] == "e2e-opaque"
        if ctx["status"] == "inspected":
            # Use active grading with response headers
            cookies_attrs = []
            for sc in (flow.response.headers.get_all("set-cookie") or [])[:10]:
                attrs = {"secure": "secure" in sc.lower(),
                         "httponly": "httponly" in sc.lower(),
                         "samesite": "strict" if "samesite=strict" in sc.lower()
                                     else "lax" if "samesite=lax" in sc.lower() else None}
                cookies_attrs.append(attrs)
            g = _sec_quality.grade_active(
                tls_version=tls_v or "13",  # mitm-decrypted ≥ TLS 1.2
                sni=host,
                headers=dict(flow.response.headers.items()),
                cookies_attrs=cookies_attrs,
            )
        else:
            g = _sec_quality.grade_passive(
                tls_version=tls_v,
                sni=host,
                is_e2e_messaging=is_e2e,
            )
        ctx["grade"] = g.get("grade", "?")
        if ctx["grade"] in ("A+", "A"):
            ctx["grade_color"] = "#00cc44"
        elif ctx["grade"] == "B":
            ctx["grade_color"] = "#88cc00"
        elif ctx["grade"] == "C":
            ctx["grade_color"] = "#ffaa00"
        else:
            ctx["grade_color"] = "#ff4466"
    except Exception:
        pass

    return ctx


def _detect_csp_strict(flow: http.HTTPFlow) -> bool:
    """Returns True if the site has a CSP that blocks inline scripts."""
    csp = flow.response.headers.get("content-security-policy", "")
    if not csp:
        return False
    csp_l = csp.lower()
    # If CSP defines script-src but doesn't include 'unsafe-inline' or nonce
    if "script-src" in csp_l or "default-src" in csp_l:
        if "'unsafe-inline'" not in csp_l and "nonce-" not in csp_l:
            return True
    return False


def _is_top_level_document(flow: http.HTTPFlow) -> bool:
    """True if the response is a top-level navigation (so the banner belongs).
    Skip iframes/sub-documents/sub-resources so we inject ONE banner per visit.
    Sec-Fetch-Dest absent (old UAs) → assume top-level (best-effort, prior behavior)."""
    dest = (flow.request.headers.get("sec-fetch-dest", "") or "").lower()
    return dest in ("", "document")


# Per-level visual theme (#545). R3 — and the planned R4 — get the
# neon-tube treatment (dark glass bar, glowing tube border + neon
# text-shadow). R2 keeps the original amber flat bar. All values are inline
# CSS only (no injected <style>/@keyframes) so it survives strict CSP and
# arbitrary third-party pages.
_LEVEL_THEME = {
    "r2": {
        "neon": False,
        "bg": "linear-gradient(90deg,#ffb347 60%,#0a0a0f 100%)",
        "fg": "#0a0a0f", "edge": "#C04E24", "accent": "#ffb347",
        "glow": "", "link": "#0a5840", "chip": "rgba(0,0,0,0.1)",
    },
    "r3": {
        "neon": True,
        "bg": "rgba(8,8,14,0.95)",
        "fg": "#e8e6d9", "edge": "#00d4ff", "accent": "#00d4ff",
        "glow": "rgba(0,212,255,0.45)", "link": "#00d4ff",
        "chip": "rgba(0,212,255,0.12)",
    },
    # planned (#545): R4 drops in with its own neon colour — inert until
    # _client_level() can return 'r4'.
    "r4": {
        "neon": True,
        "bg": "rgba(12,8,16,0.96)",
        "fg": "#e8e6d9", "edge": "#ff3df0", "accent": "#ff3df0",
        "glow": "rgba(255,61,240,0.45)", "link": "#ff3df0",
        "chip": "rgba(255,61,240,0.12)",
    },
}


def _banner_html_dynamic(sha1: str, ctx: dict, csp_strict: bool,
                          report_url: str, level_label: str,
                          level: str = "r2") -> bytes:
    """Render the injection payload.

    Two flavors depending on CSP strictness :
      - csp_strict=True  : pure HTML+inline-style, NO JS. Non-dismissible.
      - csp_strict=False : JS-driven, dismissible, dynamic insertion.

    report_url + level_label are computed by InjectBanner.response so the
    URL is reachable for the client (kbin public for R3, captive for R2)
    and the label matches the actual opt-in tier.
    """
    # Compose per-site right-side text. NCR-encode all emojis so the banner
    # renders correctly regardless of page charset (some legacy pages declare
    # iso-8859-1 which would mangle our raw UTF-8 emoji bytes).
    right_parts = [f"{_ncr(ctx['status_icon'])} {ctx['status']}"]
    # #578 — shared broadcast pin first, so every banner shows it.
    if ctx.get("pin"):
        right_parts.insert(0, "&#x1F4CC; " + _ncr(ctx["pin"]))  # 📌
    # #683 — Tor status FIRST when kbin Tor mode is armed: this flow exits via
    # Tor (anonymised). 🧅 = U+1F9C5. Most prominent chip so the client sees it.
    if ctx.get("tor_mode"):
        right_parts.insert(0, "&#x1F9C5; Tor")  # 🧅
    if ctx["flag"]:
        # Phase 6.M (#496) : flags are Unicode "regional indicator" pairs
        # (🇫🇷 = U+1F1EB + U+1F1F7). NCR-encoded pairs do NOT join into a
        # flag emoji — browsers render them as two boxed letters ("FR").
        # Emit raw UTF-8 so the font's regional-indicator-join logic works.
        # Trade-off : breaks on legacy iso-8859-1 pages (rare in 2026).
        right_parts.append(ctx["flag"])
    if ctx["app_emoji"] and ctx["app"]:
        right_parts.append(f"{_ncr(ctx['app_emoji'])} {_ncr(ctx['app'])}")
    # Phase 6.G : cookies + 1st-party tracker host (privacy signals).
    # Phase 10 perf : the per-response tracker body scan is gone — we keep
    # only the host-level flag (cheap regex on the request host).
    cookies_set = ctx.get("cookies_set", 0)
    cookies_sent = ctx.get("cookies_sent", 0)
    is_tracker = ctx.get("is_tracker_host", False)
    cookie_total = cookies_set + cookies_sent
    if cookie_total > 0:
        right_parts.append(f"&#x1F36A; {cookie_total}")  # 🍪
    if is_tracker:
        right_parts.append("&#x26A0; tracker-host")  # ⚠
    # Phase 8 (#500) — surface Utiq hits for this client. Cheap query
    # against the utiq_events store (last 1 h). Avoids surfacing the
    # tile on stale state by capping the lookback window.
    utiq_n = ctx.get("utiq_recent_count", 0)
    if utiq_n > 0:
        # 📡 N — operator-grade tracker active
        right_parts.append(f"&#x1F4E1; utiq:{utiq_n}")
    # #566 — ghost quick-stats: ads/widgets ghosted + bandwidth saved.
    g_blocked = ctx.get("ghost_blocked", 0)
    g_kb = ctx.get("ghost_kb", 0)
    if g_blocked > 0:
        # 🛡 N · ~X Ko économisés
        right_parts.append(f"&#x1F6E1; {g_blocked}&#xA0;&#x2715;&#xA0;~{g_kb}&#x202F;Ko")
    if ctx["asn"]:
        right_parts.append(_ncr(ctx["asn"]))
    # #572 — render the stats as a colourful "guirlande" of emoji chips :
    # each metric is a vibrant rounded pill with a neon glow, cycling
    # through a festive palette. Pure-ASCII styling (NCR emojis) so the
    # ascii-encode of both the CSP-strict + JS paths stays happy.
    _GUIRLANDE = ("#c9a84c", "#00d4ff", "#00ff41", "#e63946",
                  "#9e76ff", "#ff9900", "#ff5a9e", "#39ff14")
    _chips = []
    for _i, _p in enumerate(right_parts):
        _c = _GUIRLANDE[_i % len(_GUIRLANDE)]
        _chips.append(
            f"<span style=\"flex:0 0 auto;display:inline-flex;align-items:center;"
            f"background:{_c};color:#0a0a0f;padding:2px 8px;border-radius:999px;"
            f"font-weight:bold;white-space:nowrap;box-shadow:0 0 7px {_c},"
            f"inset 0 0 4px rgba(255,255,255,.3)\">{_p}</span>")
    right_text = "".join(_chips)
    grade = ctx["grade"]
    grade_color = ctx["grade_color"]
    # Static emojis used in the left-side text
    SAT_EMOJI = "&#x1F4E1;"  # 📡 satellite dish

    # ── theme resolution (#545) : R3/R4 neon tube, R2 amber flat ──
    th = _LEVEL_THEME.get(level, _LEVEL_THEME["r2"])
    # #620 redesign — three-cluster arcade HUD. box-sizing:border-box so the
    # padding never overflows the viewport width; overflow:hidden clips the
    # scrolling middle cluster. No justify-content: the middle (flex:1) does the
    # spacing, keeping the left rank+grade and the right report+close pinned.
    _base = (
        "position:fixed!important;top:0!important;left:0!important;right:0!important;"
        "z-index:2147483647!important;font-family:Menlo,Consolas,monospace!important;"
        "box-sizing:border-box!important;overflow:hidden!important;"
        "padding:5px 10px!important;font-size:11px!important;line-height:1.4!important;"
        "text-align:left!important;display:flex!important;"
        "align-items:center!important;gap:10px!important;"
    )
    if th["neon"]:
        # glowing glass tube : outer + inset accent glow, neon edge
        bar_css = (
            _base
            + f"background:{th['bg']}!important;color:{th['fg']}!important;"
            + f"border-bottom:2px solid {th['edge']}!important;"
            + f"box-shadow:0 0 10px {th['accent']},0 3px 22px {th['glow']},"
              f"inset 0 -1px 6px {th['glow']}!important;"
            + "backdrop-filter:blur(3px)!important;"
        )
        title_css = f"color:{th['accent']};text-shadow:0 0 6px {th['accent']},0 0 12px {th['accent']}"
    else:
        bar_css = (
            _base
            + f"background:{th['bg']}!important;color:{th['fg']}!important;"
            + f"border-bottom:2px solid {th['edge']}!important;"
            + "box-shadow:0 2px 8px rgba(0,0,0,0.3)!important;"
        )
        title_css = ""
    code_css = f"background:{th['chip']};padding:1px 4px;border-radius:2px"
    link_css = f"color:{th['link']};text-decoration:underline;font-weight:bold"
    title_attr = f" style=\"{title_css}\"" if title_css else ""

    # ── #620 three clusters, shared by both paths ──────────────────────────
    th_glow = th["glow"] or th["accent"]
    # LEFT pinned : rank chip (📡 ToolBoX <level>) + grade shield + CA SHA1 proof.
    # This is the "score" — the tier accent + grade colour drive the whole HUD.
    left_html = (
        f"<span style=\"flex:0 0 auto;display:flex;align-items:center;gap:6px\">"
        f"<span{title_attr} style=\"display:inline-flex;align-items:center;gap:4px;box-sizing:border-box;"
        f"padding:2px 8px;border-radius:6px;font-weight:800;color:#0a0a0f;background:{th['accent']};"
        f"box-shadow:0 0 10px {th_glow},inset 0 0 6px rgba(255,255,255,.4)\">"
        f"{SAT_EMOJI} ToolBoX {level_label}</span>"
        f"<span title=\"grade\" style=\"display:inline-flex;align-items:center;justify-content:center;"
        f"min-width:20px;height:20px;box-sizing:border-box;padding:0 4px;font-weight:900;border-radius:5px;"
        f"color:#0a0a0f;background:{grade_color};box-shadow:0 0 9px {grade_color},inset 0 0 5px rgba(0,0,0,.25)\">{grade}</span>"
        f"<code style=\"{code_css}\">{sha1[:23]}</code>"
        f"</span>"
    )
    # MIDDLE : scrolling evidence pills — flex:1, min-width:0, overflow-x:auto so
    # it shrinks/scrolls instead of pushing the report+close cluster off-screen.
    mid_html = (
        f"<span style=\"flex:1 1 auto;min-width:0;display:flex;align-items:center;gap:5px;"
        f"overflow-x:auto;white-space:nowrap\">{right_text}</span>"
    )
    # RIGHT : report CTA (both paths) + close ✕ (JS path only). flex:0 0 auto.
    report_css = (
        f"flex:0 0 auto;display:inline-flex;align-items:center;gap:4px;text-decoration:none;"
        f"font-weight:800;white-space:nowrap;color:{th['accent']};border:1px solid {th['accent']};"
        f"background:rgba(10,10,15,.55);padding:3px 9px;border-radius:6px;box-shadow:0 0 8px {th_glow}"
    )
    report_html = f"<a href=\"{report_url}\" style=\"{report_css}\">&#x1F4C4; Mon rapport</a>"
    close_css = (
        "flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;"
        "width:24px;height:24px;box-sizing:border-box;border-radius:6px;cursor:pointer;"
        f"text-decoration:none;font-weight:900;line-height:1;color:{th['fg']};"
        f"background:rgba(255,255,255,0.08);border:1px solid {th['accent']}"
    )

    if csp_strict:
        # JS-less HTML banner — visible only, no close button (non-dismissible).
        # !important everywhere so page CSS can't override the fixed positioning.
        # NCRs work even when page charset is iso-8859-1.
        html = (
            f"<div id=\"gondwana-mitm-banner\" role=\"status\" style=\"{bar_css}\">"
            + left_html + mid_html
            + f"<span style=\"flex:0 0 auto;display:flex;align-items:center;gap:8px\">{report_html}</span>"
            + "</div>"
        )
        return (b"<!-- " + _GUARD + b" -->" + html.encode("ascii"))

    # Interactive JS version. The cluster HTML already carries NCRs; json.dumps
    # (ensure_ascii=True) escapes any raw non-ASCII (geo flag) so `js.encode("ascii")`
    # stays valid. The close ✕ lives in the RIGHT pinned cluster (the responsive fix).
    import json as _json
    bar_css_js = _json.dumps(bar_css)
    left_js = _json.dumps(left_html)
    mid_js = _json.dumps(mid_html)
    report_js = _json.dumps(report_html)
    close_css_js = _json.dumps(close_css)

    js = f"""
(function(){{
  if(window.{_GUARD.decode()})return;
  window.{_GUARD.decode()}=1;
  function inject(){{
    if(!document.body)return setTimeout(inject,30);
    var b=document.createElement('div');
    b.id='gondwana-mitm-banner';
    b.setAttribute('role','status');
    b.style.cssText={bar_css_js};
    var LEFT={left_js};
    var MID={mid_js};
    var REPORT={report_js};
    var CLOSE={close_css_js};
    b.innerHTML=LEFT+MID+
      '<span style=\"flex:0 0 auto;display:flex;align-items:center;gap:8px\">'+REPORT+
        '<a href=\"javascript:void(0)\" aria-label=\"dismiss\" onclick=\"document.getElementById(\\'gondwana-mitm-banner\\').style.display=\\'none\\';document.body.style.paddingTop=0\" style=\"'+CLOSE+'\">&#x2715;</a>'+
      '</span>';
    if(document.body.firstChild){{document.body.insertBefore(b,document.body.firstChild)}}
    else{{document.body.appendChild(b)}}
    document.body.style.paddingTop='32px';
  }}
  if(document.readyState==='loading'){{document.addEventListener('DOMContentLoaded',inject)}}
  else{{inject()}}
}})();
""".strip()
    return b"<script>" + js.encode("ascii") + b"</script>"


# Phase 3 (#492) : level check — only inject banner for R2 opt-in clients
try:
    import sys as _sys
    _sys.path.insert(0, "/usr/lib/secubox/toolbox")
    from secubox_toolbox import store as _store_mod  # type: ignore
    from _common import mac_hash_of  # type: ignore
    _HAS_LEVEL = True
except Exception:
    _HAS_LEVEL = False


def _client_level(flow) -> str:
    """Returns 'r0' | 'r1' | 'r2' | 'r3'. Defaults 'r1' if lookup fails.

    Phase 6 (#496) : a peer arriving via the wg-toolbox tunnel (source IP in
    10.99.1.0/24) is by construction R3 — the only way to be on that subnet
    is to have downloaded a WG profile via /wg/profile/new AND installed our
    dedicated CA. The tunnel + cert install IS the R3 opt-in signal.
    """
    try:
        ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        if ip and ip.startswith("10.99.1."):
            return "r3"
        if not _HAS_LEVEL:
            return "r1"
        mh = mac_hash_of(ip)
        if mh:
            return _store_mod.get_client_level(mh)
    except Exception:
        pass
    return "r1"


_MAX_INJECT_BYTES = 2 * 1024 * 1024  # Phase 10 perf cap : skip injection on huge bodies


# ── #620 phase 2 : streaming loader inject (TTFB) ───────────────────────────
# When the `stream_inject` filter is ON, we stop buffering the whole HTML body
# to insert the banner. Instead we (1) strip Accept-Encoding on the document
# request so the response is identity-encoded, and (2) stream the response,
# injecting a tiny loader <script> into the first chunk that contains <head>/
# <body>. The loader (served at /__toolbox/loader.js) fetches the per-host
# bundle and renders the banner + per-page stats client-side — off the proxy
# critical path. Gated, fail-open: any miss falls back to passthrough (no
# banner on that page) or to the legacy buffer path when the body is compressed.

# ── #646 : adaptive Accept-Encoding strip ───────────────────────────────────
# Forcing identity on EVERY document pulled CSP-strict / heavy pages
# uncompressed (3-5x bytes) through the GIL-bound worker for ZERO benefit —
# streaming is disqualified on those pages anyway. So we keep gzip/br by
# default and only strip Accept-Encoding for hosts we've PROVEN
# streaming-eligible (top-level html + 2xx-3xx + r2/r3 + banner on + NOT
# CSP-strict) on a prior response. CSP-strict / non-doc hosts stay compressed
# forever (banner still injects via the buffer path, which decompresses fine).
# Per-process, in-memory, size-capped, self-healing — verdicts re-learn cheaply.
_STREAM_VERDICT: dict = {}        # host -> bool (True = strip identity & stream)
_STREAM_VERDICT_MAX = 8192


def _record_stream_verdict(host: str, eligible: bool) -> None:
    if not host:
        return
    if len(_STREAM_VERDICT) >= _STREAM_VERDICT_MAX:
        _STREAM_VERDICT.clear()   # crude self-heal; cheap to re-learn
    _STREAM_VERDICT[host] = eligible

def _stream_enabled() -> bool:
    try:
        import sys as _sys
        if "/usr/lib/secubox/toolbox" not in _sys.path:
            _sys.path.insert(0, "/usr/lib/secubox/toolbox")
        from secubox_toolbox.filters import get_filters as _gf
        return bool(_gf().get("stream_inject", False))
    except Exception:
        return False


def _loader_script(flow) -> bytes:
    """Tiny loader <script> tag carrying the client identity + WG flag."""
    mh, wg = "", "0"
    try:
        ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        if ip and ip.startswith("10.99.1."):
            wg = "1"
        if _HAS_LEVEL and ip:
            mh = mac_hash_of(ip) or ""
    except Exception:
        pass
    tag = ('<script src="/__toolbox/loader.js" data-mh="%s" data-wg="%s" async></script>'
           % (mh, wg))
    return b"<!-- " + _GUARD + b" -->" + tag.encode("ascii", "ignore")


class _LoaderInjector:
    """Stream modifier: inject `script` once, in the first chunk holding
    <head>/<body>. Never holds bytes back (TTFB-safe); gives up after 128 KB."""

    def __init__(self, script: bytes):
        self.script = script
        self.done = False
        self.seen = 0

    def __call__(self, data: bytes) -> bytes:
        if self.done or not data or self.seen > 131072:
            self.seen += len(data or b"")
            return data
        self.seen += len(data)
        low = data.lower()
        h = low.find(b"<head")
        if h >= 0:
            j = data.find(b">", h)
            if j >= 0:
                self.done = True
                return data[:j + 1] + self.script + data[j + 1:]
        b = low.find(b"<body")
        if b >= 0:
            self.done = True
            return data[:b] + self.script + data[b:]
        return data


class InjectBanner:
    def request(self, flow: http.HTTPFlow) -> None:
        # #636 — serve the banner loader + bundle for ANY origin so the injected
        # <script src="/__toolbox/loader.js"> resolves (R3 clients hit arbitrary
        # hosts whose origin can't serve /__toolbox/*). Short-circuit upstream.
        try:
            p = flow.request.path or ""
            # NOTE: startswith (not ==) is REQUIRED: flow.request.path includes
            # the query string, and the loader fetches /__toolbox/bundle?mh=..&wg=..
            # — an exact-match would never fire for the bundle. Do not "tighten".
            # The bundle echoes a caller-supplied mh + store.get_client_level(mh)
            # unauthenticated — intentional, same as the portal /__toolbox/bundle
            # endpoint; trust boundary is the R3 nftables perimeter (these workers
            # are not externally reachable).
            if p.startswith("/__toolbox/loader.js"):
                from secubox_toolbox import bundle as _b
                flow.response = http.Response.make(
                    200, _b.LOADER_JS.encode("utf-8"),
                    {"Content-Type": "application/javascript",
                     "Cache-Control": "public, max-age=3600"})
                return
            if p.startswith("/__toolbox/bundle"):
                from secubox_toolbox import bundle as _b
                import json as _json
                q = flow.request.query
                mh = q.get("mh", "") if q else ""
                wg = (q.get("wg", "0") if q else "0") in ("1", "true", "yes", "on")
                flow.response = http.Response.make(
                    200, _json.dumps(_b.get_bundle(mh, wg)).encode("utf-8"),
                    {"Content-Type": "application/json",
                     "Cache-Control": "no-store"})
                return
        except Exception as e:
            log.warning("toolbox asset serve failed for %s: %s", flow.request.path, e)
        # #620/#646 : for top-level HTML navigations to hosts PROVEN
        # streaming-eligible, ask upstream for identity encoding so we can
        # stream-inject the loader without decompressing. Unknown / CSP-strict
        # hosts keep their gzip/br compression (learned in responseheaders).
        if not _stream_enabled():
            return
        try:
            req = flow.request
            accept = (req.headers.get("accept", "") or "").lower()
            dest = (req.headers.get("sec-fetch-dest", "") or "").lower()
            is_doc = dest == "document" or "text/html" in accept
            if is_doc and _STREAM_VERDICT.get(flow.request.pretty_host or ""):
                if "accept-encoding" in req.headers:
                    req.headers["accept-encoding"] = "identity"
        except Exception:
            pass

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # #620 : set up streaming injection BEFORE the body is read. Falls back
        # to the legacy buffer path (response hook) if anything disqualifies.
        if not _stream_enabled():
            return
        resp = flow.response
        if not resp:
            return
        ct = (resp.headers.get("content-type", "") or "").lower()
        if "text/html" not in ct:
            return
        if resp.status_code < 200 or resp.status_code >= 400:
            return
        if _client_level(flow) not in ("r2", "r3"):
            return
        try:
            import sys as _sys
            if "/usr/lib/secubox/toolbox" not in _sys.path:
                _sys.path.insert(0, "/usr/lib/secubox/toolbox")
            from secubox_toolbox.filters import get_filters as _gf
            if not _gf().get("banner", True):
                return
        except Exception:
            pass
        # #646 — learn per-host streaming eligibility from THIS response, so the
        # next visit's request() knows whether to strip Accept-Encoding. This is
        # independent of the current encoding: a host eligible today is worth
        # asking identity from tomorrow. #636 — strict CSP blocks the injected
        # loader <script>; #639 — only top-level navigations get the banner.
        # Both disqualify streaming → ineligible → keep compression.
        eligible = _is_top_level_document(flow) and not _detect_csp_strict(flow)
        _record_stream_verdict(flow.request.pretty_host or "", eligible)
        if not eligible:
            return
        # Compressed (upstream ignored our identity request, or this is the first
        # visit before we'd learned to ask identity) → let the buffer path handle
        # it (mitmproxy auto-decodes there). Can only stream an identity body.
        if resp.headers.get("content-encoding"):
            return
        try:
            resp.stream = _LoaderInjector(_loader_script(flow))
            flow.metadata["sbx_streamed"] = True
        except Exception as e:
            log.warning("stream-inject setup failed for %s: %s", flow.request.host, e)

    def response(self, flow: http.HTTPFlow) -> None:
        # #620 : already handled by the streaming injector — skip the buffer path.
        if flow.metadata.get("sbx_streamed"):
            return
        if not flow.response:
            return
        ct = flow.response.headers.get("content-type", "")
        if "text/html" not in ct.lower():
            return
        if flow.response.status_code < 200 or flow.response.status_code >= 400:
            return
        # Phase 3 (#492) + Phase 6 (#496) : banner fires for R2 (captive opt-in)
        # AND R3 (portable WG opt-in). R0/R1 stay banner-free.
        if _client_level(flow) not in ("r2", "r3"):
            return
        # #566 — modular filter toggle (toolbox WebUI). Banner can be
        # disabled without touching the addon list.
        try:
            import sys as _sys
            if "/usr/lib/secubox/toolbox" not in _sys.path:
                _sys.path.insert(0, "/usr/lib/secubox/toolbox")
            from secubox_toolbox.filters import get_filters as _gf
            if not _gf().get("banner", True):
                return
        except Exception:
            pass
        # #639 — only inject into top-level navigations; iframes/sub-documents
        # share the same buffer path and would each get a banner.
        if not _is_top_level_document(flow):
            return
        # Phase 10 perf : cheap pre-flight check on Content-Length to avoid
        # reading multi-MB bodies into RAM just to discover we'd skip them.
        # `flow.response.content` would buffer the whole body before returning.
        try:
            cl = int(flow.response.headers.get("content-length", "0") or "0")
            if cl > _MAX_INJECT_BYTES:
                return
        except (TypeError, ValueError):
            pass
        body = flow.response.content
        if body is None or _GUARD in body:
            return
        if len(body) > _MAX_INJECT_BYTES:
            # Streamed bodies without content-length still get caught here.
            return
        m = _RE_BODY_CLOSE.search(body)
        if not m:
            return
        # Phase 3 : compute per-site context + CSP awareness
        # Phase 6 (#496) : flow-aware report URL (kbin public for R3, captive
        # for R2) + level label ("R2" vs "R3")
        try:
            ctx = _compute_site_context(flow)
            # #566 — ghost quick-stats (ads/widgets ghosted + KB saved).
            try:
                import json as _json
                with open("/run/secubox/ghost.json", "r", encoding="utf-8") as _gf2:
                    _g = _json.load(_gf2)
                ctx["ghost_blocked"] = int(_g.get("blocked_requests", 0))
                ctx["ghost_kb"] = int(_g.get("bytes_saved_est", 0)) // 1024
            except Exception:
                ctx["ghost_blocked"] = 0
                ctx["ghost_kb"] = 0
            # #578 — shared broadcast pin (operator/top-1), shown in every
            # client's banner. Fresh window 24 h.
            ctx["pin"] = ""
            try:
                import json as _json
                import time as _time
                with open("/run/secubox/pin.json", "r", encoding="utf-8") as _pf:
                    _p = _json.load(_pf)
                if _p.get("text") and (_time.time() - _p.get("ts", 0)) < 86400:
                    ctx["pin"] = str(_p["text"])[:80]
            except Exception:
                pass
            csp_strict = _detect_csp_strict(flow)
            report_url = _report_url_for(flow)
            level_label = _level_label(flow)
            level = _client_level(flow)
            # #566 — R3+/R4 is an active-protection tier (spoof + ghost),
            # not mere inspection: relabel the banner status accordingly.
            if level in ("r3", "r4") and ctx.get("status") == "inspected":
                ctx["status"] = "protected"
                ctx["status_icon"] = "\U0001F6E1"  # 🛡
            snippet = _banner_html_dynamic(_CA_SHA1, ctx, csp_strict,
                                            report_url, level_label, level)
        except Exception as e:
            log.warning("banner compute failed for %s: %s", flow.request.host, e)
            # Fail-open : skip injection rather than break the page
            return
        new_body = body[: m.start()] + snippet + body[m.start():]
        flow.response.content = new_body


addons = [InjectBanner()]
