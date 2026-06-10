# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""
SecuBox-Deb :: ToolBoX MITM addon — social_graph

Phase 11.A (#505, parent #502) — passive correlation of cross-site
tracker identifiers per R2/R3 consented peer.

The addon listens on the response hook (where Set-Cookie is sent by
the 3rd-party server) AND on the request hook (where the Cookie
header is sent back by the browser). For each cookie observed :

  * Decide if the COOKIE-issuing domain is 3rd-party relative to the
    1st-party host the browser was visiting.
  * Reject deny-listed names (session, CSRF, auth, locale …).
  * Hash the identifier (`sha256(domain || name || value)[:16]`) so
    we have a stable but non-round-trippable key.
  * Submit an edge record off-thread via secubox_toolbox.social.

Key invariants :

  * Never persists raw cookie values.
  * Never blocks the asyncio loop — every write is fire-and-forget.
  * Only fires when the peer is a known R2/R3 client (mac_hash
    available). R0/R1 flows are ignored.
  * The 1st-party `src_site` is derived from the request host's
    registrable domain (eTLD+1 via a small inline PSL approximation).
  * 3rd-party check : tracker_domain != src_site (eTLD+1 compare).

Phase 10 banner-perf already brought the response hook latency down ;
this addon stays cheap by deferring ALL persistence to the executor
and doing the parsing on a string-only fast path.
"""
from __future__ import annotations

import logging
import re
from typing import Iterable, List, Optional

from mitmproxy import http

try:  # Best-effort — same defensive import as other toolbox addons
    from secubox_toolbox import social as _social
except Exception:  # pragma: no cover — when running outside the toolbox tree
    _social = None

# Hash + deny-list helpers live in secubox_toolbox.social so they're
# unit-testable on the host side without spinning a mitmproxy flow.

log = logging.getLogger("secubox.toolbox.addon.social_graph")


# ─── eTLD+1 (registrable-domain) approximation ───
# Phase 11.A ships a regex-based approximation that covers > 99 % of the
# tracker / publisher ecosystem we see on a French civic kiosk.  A
# proper publicsuffix.org tree fold lands in Phase A.1 if needed.
_MULTI_LABEL_TLDS = {
    "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk",
    "co.jp", "ne.jp", "ac.jp",
    "com.au", "net.au", "org.au",
    "com.br", "com.cn", "com.hk", "com.tw", "com.mx",
}


def _registrable_domain(host: str) -> str:
    """Cheap eTLD+1 extraction.  e.g.
    `www.lemonde.fr` → `lemonde.fr`
    `cdn.api.example.co.uk` → `example.co.uk`
    `tracker.com` → `tracker.com`
    """
    h = (host or "").lower().strip(".")
    if not h or h.replace(".", "").isdigit():  # raw IP
        return h
    parts = h.split(".")
    if len(parts) < 2:
        return h
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_LABEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


# ─── peer identity ───
# Phase 11.A originally tried `from . import local_store` which silently
# failed because mitmproxy loads addons as top-level modules (not as
# package members), so the relative import never resolved.  Inlined
# here — only the R3 path (peer IP in 10.99.1.0/24 → WG pubkey hash)
# since Phase B is R3-only.  R2 captive lookup remains in local_store
# and joins later when the addon is wired into the captive mitm.
import hashlib as _hashlib
import json as _json
from pathlib import Path as _Path

_WG_PEERS_DB = _Path("/var/lib/secubox/toolbox/wg-peers.json")
_WG_PEERS_CACHE: dict = {}
_WG_PEERS_MTIME: float = 0.0


def _wg_hash_of(ip: str) -> Optional[str]:
    global _WG_PEERS_MTIME
    try:
        if not _WG_PEERS_DB.exists():
            return None
        mtime = _WG_PEERS_DB.stat().st_mtime
        if mtime != _WG_PEERS_MTIME or not _WG_PEERS_CACHE:
            data = _json.loads(_WG_PEERS_DB.read_text()).get("peers", {})
            _WG_PEERS_CACHE.clear()
            for pubkey, meta in data.items():
                peer_ip = meta.get("ip")
                if peer_ip:
                    _WG_PEERS_CACHE[peer_ip] = _hashlib.sha256(
                        pubkey.encode()
                    ).hexdigest()[:16]
            _WG_PEERS_MTIME = mtime
        return _WG_PEERS_CACHE.get(ip)
    except Exception:
        return None


def _client_mac_hash(flow) -> Optional[str]:
    try:
        if flow.client_conn and flow.client_conn.peername:
            ip = flow.client_conn.peername[0]
            if ip and ip.startswith("10.99.1."):
                return _wg_hash_of(ip)
    except Exception:
        pass
    return None


# ─── cookie parsers ───
_SET_COOKIE_NAMEVAL = re.compile(r"^\s*([^=;]+)\s*=\s*([^;]*)")
_COOKIE_PAIR = re.compile(r"\s*([^=;]+)\s*=\s*([^;]*)")


def _parse_set_cookie(header: str) -> Optional[tuple]:
    """Return (name, value) for a Set-Cookie header, or None on garbage."""
    m = _SET_COOKIE_NAMEVAL.match(header or "")
    if not m:
        return None
    name = m.group(1).strip()
    value = m.group(2).strip()
    if not name:
        return None
    return name, value


def _parse_cookie_header(header: str) -> List[tuple]:
    """Return [(name, value), …] for a Cookie header (browser→server)."""
    out: List[tuple] = []
    for part in (header or "").split(";"):
        m = _COOKIE_PAIR.match(part)
        if m:
            name = m.group(1).strip()
            value = m.group(2).strip()
            if name:
                out.append((name, value))
    return out


# ─── JA4 lookup ───
def _ja4_hash(flow) -> Optional[str]:
    """Pull the JA4 fingerprint set by the ja4 addon, if present."""
    try:
        ja4 = (flow.metadata or {}).get("ja4")
        if ja4:
            return str(ja4)[:32]
    except Exception:
        pass
    return None


# ─── consent-platform detection (Phase 11.C #508) ───
#
# We detect the four dominant CMP (Consent Management Platform) cookies.
# Their PRESENCE on a flow means the user has interacted with the consent
# banner on this site at least once.  We track, per (peer, site) :
#   - whether the site is KNOWN to run a CMP (we've seen the cookie OR the
#     loader path), and
#   - whether a consent cookie has been observed yet.
# This lets us classify each tracker edge as pre/post/none-consent.
#
# Names are matched case-insensitively as a prefix (OneTrust appends
# region suffixes, Didomi rotates tokens, etc.).
_CMP_COOKIE_PREFIXES = (
    "optanonconsent", "onetrustconsent", "optanonalertboxclosed",  # OneTrust
    "didomi_token", "euconsent-v2",                                 # Didomi / IAB TCF
    "__qca", "quantcast",                                           # Quantcast
    "sp_choice", "consentuid", "_sp_",                              # Sourcepoint
)
# CMP loader URL fragments — seeing the site REQUEST one of these proves
# the site runs a consent platform even before the cookie is set.
_CMP_LOADER_FRAGMENTS = (
    "cdn.cookielaw.org", "onetrust.com",      # OneTrust
    "sdk.privacy-center.org", "didomi.io",    # Didomi
    "quantcast.mgr.consensu.org", "quantcast.com/choice",  # Quantcast
    "sourcepoint.mgr.consensu.org", "sp-prod.net",          # Sourcepoint
)

# Per-(peer, site) consent observation log.  Bounded soft-cap : if it
# grows past 20k entries we drop it wholesale (a fresh session rebuild is
# cheap and the salt rotates daily anyway).
_consent_log: dict = {}


def _consent_key(mac_hash: str, site: str) -> tuple:
    return (mac_hash, site)


def _update_consent_log(mac_hash: str, src_site: str, flow) -> None:
    """Observe whether this flow reveals a CMP cookie or loader for the
    (peer, site) pair, and update the in-memory log."""
    try:
        if len(_consent_log) > 20000:
            _consent_log.clear()
        key = _consent_key(mac_hash, src_site)
        state = _consent_log.get(key, {"has_cmp": False, "consented": False})

        # 1) CMP loader request → the site runs a consent platform.
        url = (flow.request.pretty_url or "").lower()
        if any(frag in url for frag in _CMP_LOADER_FRAGMENTS):
            state["has_cmp"] = True

        # 2) CMP cookie present (either direction) → consent recorded.
        cookie_blobs = []
        cookie_blobs.extend(flow.request.headers.get_all("cookie") or [])
        cookie_blobs.extend(flow.response.headers.get_all("set-cookie") or [])
        for blob in cookie_blobs:
            low = blob.lower()
            for pref in _CMP_COOKIE_PREFIXES:
                if pref in low:
                    state["has_cmp"] = True
                    state["consented"] = True
                    break
        _consent_log[key] = state
    except Exception:
        pass


def _consent_state_for(mac_hash: str, site: str) -> str:
    """Classify the current consent state for the (peer, site) pair.

    Evidence-only semantics (no interpretation beyond the observation) :
      post_consent — a CMP cookie has been seen here for this peer.
      pre_consent  — the site runs a CMP (loader/cookie seen) but no
                     consent cookie yet : a tracker firing now fires
                     before consent.
      none_seen    — no CMP detected at all ; we make no claim.
    """
    st = _consent_log.get(_consent_key(mac_hash, site))
    if not st:
        return "none_seen"
    if st.get("consented"):
        return "post_consent"
    if st.get("has_cmp"):
        return "pre_consent"
    return "none_seen"


# ─── CDN / edge-network detection (Phase 12.A #515) ───
# Passive : classify the CDN fronting a host from its response headers.
# A shared CDN seeing the same browser across sites is itself a
# cross-site correlation surface — worth surfacing as its own lens.
def detect_cdn(headers) -> tuple:
    """Return (cdn_vendor, cache_status) from response headers, best-effort.

    `headers` is mitmproxy's Headers (case-insensitive .get).  Returns
    (None, None) when no CDN signature is present.
    """
    def g(name):
        try:
            return (headers.get(name) or "").lower()
        except Exception:
            return ""

    server = g("server")
    via = g("via")
    x_cache = g("x-cache")
    x_served = g("x-served-by")

    # Cloudflare
    if g("cf-ray") or g("cf-cache-status") or "cloudflare" in server:
        return "Cloudflare", (g("cf-cache-status") or x_cache or None)
    # Fastly (Varnish-based, x-served-by cache nodes)
    if "fastly" in via or "fastly" in x_served or ("cache-" in x_served):
        return "Fastly", (x_cache or None)
    # Akamai
    if "akamaighost" in server or g("x-akamai-transformed") or g("x-akamai-request-id"):
        return "Akamai", (x_cache or None)
    # Amazon CloudFront
    if g("x-amz-cf-id") or "cloudfront" in via or "cloudfront" in x_cache:
        return "CloudFront", (x_cache or None)
    # Google edge
    if "google" in via or g("x-goog-generation") or g("x-goog-meta"):
        return "Google", None
    # Vercel / Netlify / Bunny / KeyCDN / Sucuri / Imperva
    if g("x-vercel-cache") or "vercel" in server:
        return "Vercel", (g("x-vercel-cache") or None)
    if g("x-nf-request-id") or "netlify" in server:
        return "Netlify", None
    if g("cdn-cache") or "bunnycdn" in server or g("x-bunny-cache"):
        return "BunnyCDN", None
    if "keycdn" in server or g("x-edge-location"):
        return "KeyCDN", None
    if g("x-sucuri-id") or g("x-sucuri-cache"):
        return "Sucuri", (g("x-sucuri-cache") or None)
    if g("x-iinfo") or "incapsula" in g("set-cookie"):
        return "Imperva/Incapsula", None
    # Generic edge-cache tell (x-cache HIT/MISS without a known vendor)
    if x_cache or x_served:
        return "edge-cache", (x_cache or None)
    return None, None


# ─── JA4 lookup ───
def _ja4_hash(flow) -> Optional[str]:
    """Pull the JA4 fingerprint set by the ja4 addon, if present."""
    try:
        ja4 = (flow.metadata or {}).get("ja4")
        if ja4:
            return str(ja4)[:32]
    except Exception:
        pass
    return None


# ─── main ───
class SocialGraph:
    """mitmproxy addon : record cookie-bearing edges per R2/R3 peer."""

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response or _social is None:
            return
        mac_hash = _client_mac_hash(flow)
        if not mac_hash:
            return

        src_site = _registrable_domain(flow.request.host)
        if not src_site:
            return

        # Phase 11.C (#508) — consent-state detection.  Before recording
        # any edge, update our per-peer × per-site consent log : has a
        # consent-platform cookie (OneTrust / Didomi / Quantcast /
        # Sourcepoint) been observed for this peer on this site yet ?
        # The edge's consent_state is then :
        #   post_consent  — a consent cookie was already seen here
        #   pre_consent   — NOT yet seen, AND the site DOES run a consent
        #                   platform somewhere (so a tracker firing now is
        #                   firing before consent — RGPD art. 6.1.a + 7)
        #   none_seen     — no consent platform detected for this site at
        #                   all (we make no claim ; baseline)
        _update_consent_log(mac_hash, src_site, flow)
        consent_state = _consent_state_for(mac_hash, src_site)

        # Phase 12.A (#515) — passive CDN detection on the responding host.
        # Host-stable, mac-independent ; upserted off-thread.  We only
        # record for 3rd-party hosts (the ones that become graph nodes).
        try:
            resp_host = _registrable_domain(flow.request.host)
            if resp_host and resp_host != src_site:
                cdn_vendor, cache_status = detect_cdn(flow.response.headers)
                if cdn_vendor:
                    _social.record_host_cdn(
                        domain=resp_host,
                        cdn_vendor=cdn_vendor,
                        cache_status=cache_status,
                    )
        except Exception:
            pass

        # Set-Cookie headers : the 3rd-party server hands a new identifier.
        # The Set-Cookie domain may differ from flow.request.host (Set-Cookie
        # `Domain=` attribute) — when present, we trust that for the
        # tracker_domain ; else fall back to the request host's eTLD+1.
        ja4 = _ja4_hash(flow)
        for sc in (flow.response.headers.get_all("set-cookie") or [])[:50]:
            parsed = _parse_set_cookie(sc)
            if not parsed:
                continue
            name, value = parsed
            if _social.is_deny_listed(name):
                continue
            # `Domain=…` attribute parsing
            domain_attr = _extract_domain_attr(sc)
            tracker_domain = _registrable_domain(domain_attr or flow.request.host)
            if not tracker_domain or tracker_domain == src_site:
                # 1st-party Set-Cookie : not a cross-site tracker signal.
                continue
            cid = _social.cookie_id_hash(tracker_domain, name, value)
            _social.record_edge(
                client_mac_hash=mac_hash,
                src_site=src_site,
                tracker_domain=tracker_domain,
                cookie_id_hash_val=cid,
                ja4_hash=ja4,
                consent_state=consent_state,
            )

        # Request-side Cookie headers (only meaningful when the
        # request was for a 3rd-party domain : a 1st-party context
        # browsing site X sends Cookie headers to embedded tracker T).
        cookie_hdrs = flow.request.headers.get_all("cookie") or []
        if not cookie_hdrs:
            return

        # The host we're sending the Cookie to is the tracker (because
        # this is a 3rd-party request).  We use the Referer / Origin
        # to figure out which 1st-party context originated the load.
        tracker_domain = _registrable_domain(flow.request.host)
        if not tracker_domain:
            return
        ctx_site = _src_site_from_referer(flow)
        if not ctx_site or ctx_site == tracker_domain:
            # Either no Referer (direct nav, not interesting for
            # cross-site mapping) or self-referential (the tracker
            # called itself).
            return

        ctx_consent = _consent_state_for(mac_hash, ctx_site)
        for hdr in cookie_hdrs[:5]:
            for name, value in _parse_cookie_header(hdr)[:50]:
                if _social.is_deny_listed(name):
                    continue
                cid = _social.cookie_id_hash(tracker_domain, name, value)
                _social.record_edge(
                    client_mac_hash=mac_hash,
                    src_site=ctx_site,
                    tracker_domain=tracker_domain,
                    cookie_id_hash_val=cid,
                    ja4_hash=ja4,
                    consent_state=ctx_consent,
                )


_DOMAIN_ATTR_RE = re.compile(r"(?i);\s*domain\s*=\s*([^;]+)")


def _extract_domain_attr(set_cookie_header: str) -> Optional[str]:
    """Pull the `; Domain=…` attribute from a Set-Cookie line, if any."""
    m = _DOMAIN_ATTR_RE.search(set_cookie_header or "")
    if not m:
        return None
    return m.group(1).strip().lstrip(".").lower() or None


def _src_site_from_referer(flow) -> Optional[str]:
    """Derive the 1st-party site for a 3rd-party request.

    Tries Referer first, then Origin.  Returns the registrable domain
    of the originating page, NOT the tracker host itself.
    """
    ref = flow.request.headers.get("referer") or flow.request.headers.get("origin")
    if not ref:
        return None
    # Strip scheme + path.
    s = ref.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    return _registrable_domain(s)


addons = [SocialGraph()]
