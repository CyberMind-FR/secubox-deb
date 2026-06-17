# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: Anti-Track v2 hot-path addon (#633)

Applies privacy.verdict() per request: allow | block(204) | poison, plus
always-on anonymize. Thin by design — no classification or state math here.
Doctrine: DEFAULT OFF (privacy_enforce=false → observe-only), LOGGED, fail-safe
(any error → allow + anonymize, never 500 the client's page).
"""
from __future__ import annotations

import logging
import os
import sys
import time

from mitmproxy import http

if "/usr/lib/secubox/toolbox" not in sys.path:
    sys.path.insert(0, "/usr/lib/secubox/toolbox")
from secubox_toolbox import privacy            # noqa: E402
from secubox_toolbox.filters import get_filters  # noqa: E402
from _common import mac_hash_of                 # noqa: E402

log = logging.getLogger("secubox.toolbox.privacy_guard")
_AUDIT = "/var/log/secubox/audit.log"
_STATS = "/run/secubox/privacy.json"

# operator/carrier + re-identification headers stripped on every flow (anonymize)
_STRIP = (
    "msisdn", "x-msisdn", "x-up-calling-line-id", "x-up-subno",
    "x-nokia-msisdn", "x-acr", "x-vf-acr", "x-amobee-1", "x-amobee-2",
    "tm-user-id", "x-wap-profile", "x-wap-msisdn", "x-network-info",
    "x-forwarded-for", "forwarded", "x-real-ip", "via",
)
_BEACON_PATHS = ("/collect", "/pixel", "/track", "/beacon", "/b/ss", "/p.gif",
                 "/__utm.gif", "/ga", "/g/collect", "/tr")
_counts = {"blocks": 0, "poisons": 0, "anonymized": 0, "observed": 0,
           "since": int(time.time())}
_last_flush = 0.0


def _client_hash(flow: http.HTTPFlow):
    try:
        return mac_hash_of(flow.client_conn.peername[0])
    except Exception:
        return None


def _beacon_hint(flow: http.HTTPFlow) -> bool:
    accept = (flow.request.headers.get("accept") or "").lower()
    path = (flow.request.path or "").lower()
    if "text/html" in accept:
        return False
    return any(p in path for p in _BEACON_PATHS) or accept in ("*/*", "")


def _site_of(flow: http.HTTPFlow) -> str:
    # No Referer (top-level navigation, or Referrer-Policy stripping) → fall back
    # to the request host, so under Fort-Knox the flow is treated as first-party.
    # Intentionally permissive: we never want to break a navigation (fail open).
    ref = flow.request.headers.get("referer") or ""
    if ref:
        try:
            from urllib.parse import urlparse
            return urlparse(ref).hostname or flow.request.pretty_host or ""
        except Exception:
            pass
    return flow.request.pretty_host or ""


def _audit(action: str, host: str, detail: str) -> None:
    try:
        with open(_AUDIT, "a", encoding="utf-8") as f:
            f.write("%s privacy %s host=%s %s\n" % (
                time.strftime("%Y-%m-%dT%H:%M:%S%z"), action, host, detail))
    except Exception:
        pass


def _flush(force: bool = False) -> None:
    global _last_flush
    now = time.time()
    if not force and (now - _last_flush) < 5:
        return
    _last_flush = now
    try:
        import json
        os.makedirs(os.path.dirname(_STATS), exist_ok=True)
        with open(_STATS, "w", encoding="utf-8") as f:
            json.dump({**_counts, "updated": int(now)}, f)
    except Exception:
        pass


def _anonymize(flow: http.HTTPFlow) -> None:
    for h in _STRIP:
        if h in flow.request.headers:
            del flow.request.headers[h]
    flow.request.headers["DNT"] = "1"
    flow.request.headers["Sec-GPC"] = "1"


class PrivacyGuard:
    """Apply the layered Anti-Track verdict in the hot path."""

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        try:
            f = get_filters()
            if not f.get("privacy_enforce"):
                if privacy.is_tracker(flow.request.pretty_host or ""):
                    _counts["observed"] += 1
                    _flush()
                return

            host = flow.request.pretty_host or ""
            site = _site_of(flow)
            fortknox = privacy.registrable(site) in set(f.get("fortknox_sites") or [])
            v = privacy.verdict(host, site, beacon_hint=_beacon_hint(flow),
                                fortknox=fortknox)

            if v == "block":
                flow.response = http.Response.make(204, b"", {})
                _counts["blocks"] += 1
                _audit("block", host, "path=%s" % (flow.request.path or "")[:80])
            elif v == "poison" and f.get("privacy_poison"):
                self._poison(flow, host)

            if v != "block" and f.get("privacy_anonymize"):
                _anonymize(flow)
                _counts["anonymized"] += 1
            _flush()
        except Exception as e:
            log.debug("privacy_guard requestheaders error: %s", e)
            try:
                _anonymize(flow)
            except Exception:
                pass

    def _poison(self, flow: http.HTTPFlow, host: str) -> None:
        ch = _client_hash(flow)
        cookie = flow.request.headers.get("cookie")
        if not ch or not cookie:
            if cookie:
                del flow.request.headers["cookie"]
            return
        forged = []
        for part in cookie.split(";"):
            if "=" not in part:
                continue  # malformed / attribute-only fragment → drop
            name, _, _val = part.strip().partition("=")
            fake = privacy.fake_id(ch, host, name)
            if fake:
                forged.append("%s=%s" % (name, fake))
            # fake is None (no jar key) → omit the cookie entirely (fail private)
        if forged:
            flow.request.headers["cookie"] = "; ".join(forged)
        else:
            del flow.request.headers["cookie"]
        if "referer" in flow.request.headers:
            flow.request.headers["referer"] = "https://%s/" % (
                privacy.registrable(host) or host)
        _counts["poisons"] += 1
        _audit("poison", host, "cookies=%d" % len(forged))

addons = [PrivacyGuard()]
