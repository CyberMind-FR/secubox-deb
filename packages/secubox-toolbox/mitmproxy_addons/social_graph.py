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
