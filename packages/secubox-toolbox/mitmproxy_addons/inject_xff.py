# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Phase 7 follow-up (#498) — propagate the original WG peer IP on every
# request mitm-wg proxies upstream.
#
# Why : the R3 verification page (and any other in-tunnel UI) needs to
# know "this user came in through the WireGuard tunnel" to surface
# the right banner / report URL. Without an XFF header the upstream
# (HAProxy → nginx → toolbox FastAPI) only sees mitm-wg's own outbound
# IP (the box's WAN once the request bounces through the home router)
# and concludes the user is OFF-tunnel.
#
# This addon attaches `X-Forwarded-For` carrying flow.client_conn.peername
# and a sentinel `X-Through-R3-Tunnel: 1` for backend detection that
# doesn't rely on XFF parsing.

from mitmproxy import http


class InjectXff:
    """Add X-Forwarded-For + X-Through-R3-Tunnel before mitmproxy hands
    the request to the upstream connector. Runs at requestheaders so the
    headers are set before any addon that might short-circuit the flow."""

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        try:
            peer = flow.client_conn.peername
            if not peer:
                return
            peer_ip = peer[0]
            # Append to existing XFF chain (don't clobber upstream proxies
            # if any are present before mitm-wg, however unlikely).
            existing = flow.request.headers.get("X-Forwarded-For")
            new_xff = f"{existing}, {peer_ip}" if existing else peer_ip
            flow.request.headers["X-Forwarded-For"] = new_xff
            # Sentinel header : easier for backends to detect than parsing
            # XFF for `10.99.1.*`. Set only when peer is on the WG subnet
            # so non-tunnel paths through this proxy (none today) stay clean.
            if peer_ip.startswith("10.99.1."):
                flow.request.headers["X-Through-R3-Tunnel"] = "1"
                flow.request.headers["X-R3-Peer"] = peer_ip
        except Exception:
            # Never break the flow on a header-tagging failure.
            pass


addons = [InjectXff()]
