# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Phase 8 (#500) — anti-Utiq defense (Quick Win : R0 log + R1 block).
#
# Utiq is the operator-grade tracking ID launched in 2023 by Deutsche
# Telekom + Orange + Telefónica + Vodafone. Sites participating include
# a loader at `<sitename>.utiq.com/utiqLoader.js` (a 1st-party CNAME)
# that calls the Utiq API ; the carrier validates the request via
# network-level SIM/IP headers and returns a 90-day-stable identifier
# (martechpass = mtid) the publisher can use to track the user across
# visits. Unlike cookies, the user cannot delete a mtid client-side —
# only the carrier's `consenthub.utiq.com` consent record controls it.
#
# Defense levels (per-client, opt-in) :
#   R0  log only — passthrough, record every flow involving Utiq
#                  hosts so the operator sees what's happening.
#   R1  block    — refuse the loader + API calls.  No mtid is ever
#                  emitted to the publisher.  Some pages may degrade
#                  (the Utiq tag is usually wrapped in `if (mtid)`,
#                  so the worst case is no targeted ad).
#   R2  mask     — (Phase 2, future) return a stub `utiqLoader.js`
#                  that sets `window.utiq = {mtid: null, atid: null}`
#                  so the page sees a "no consent" state.
#   R3  pseudo   — (Phase 2, future) forge a stable-per-publisher
#                  pseudo-mtid via avatar.py to poison the tracking
#                  pool.
#
# This Quick Win ships R0 + R1.  Levels R2 / R3 land in Phase 2.

from __future__ import annotations

import logging
import re

from mitmproxy import http

# Importing the toolbox state store is best-effort : the addon must
# still load even when the host doesn't have the toolbox package
# installed (e.g. a standalone mitmproxy install).
try:
    from secubox_toolbox import utiq as _store
except Exception:
    _store = None

log = logging.getLogger("secubox.toolbox.utiq")


# ── Host + path matchers ──
# *.utiq.com covers consenthub.utiq.com + every <publisher>.utiq.com
# CNAME wrapper. The path matcher catches the loader regardless of
# subdomain ; some publishers proxy `utiqLoader.js` through their own
# 1st-party path (`/static/js/utiqLoader.js`) to bypass simple host
# filters.
_RE_HOST = re.compile(r"(^|\.)utiq\.com$", re.IGNORECASE)
_RE_PATH = re.compile(r"utiqLoader\.js", re.IGNORECASE)


def _is_utiq_flow(flow: http.HTTPFlow) -> bool:
    host = flow.request.pretty_host or ""
    if _RE_HOST.search(host):
        return True
    if _RE_PATH.search(flow.request.path or ""):
        return True
    return False


def _client_ip(flow: http.HTTPFlow) -> str | None:
    try:
        return flow.client_conn.peername[0]
    except Exception:
        return None


def _level(flow: http.HTTPFlow) -> str:
    """Return the current defense level for the client behind this flow.

    Phase 8 Quick Win — defaults to R0 (log) for every client.  Per-
    client level customisation comes in Phase 2 when the admin UI
    exposes the per-client toggle.  In the meantime an operator can
    override via env var `UTIQ_DEFAULT_LEVEL=R1` to flip everyone to
    block mode globally.
    """
    import os
    return (os.environ.get("UTIQ_DEFAULT_LEVEL") or "R0").upper()


class UtiqDefense:
    """Detect, log, and (R1) block Utiq tracking flows."""

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # We hook requestheaders rather than request so we can RST the
        # connection BEFORE the body is fetched (saves bandwidth on a
        # blocked utiqLoader.js).
        if not _is_utiq_flow(flow):
            return

        client_ip = _client_ip(flow)
        host = flow.request.pretty_host or ""
        path = flow.request.path or ""
        level = _level(flow)

        # Always log, regardless of level — that's the R0 baseline.
        if _store is not None:
            try:
                _store.record_event(
                    client_ip=client_ip,
                    host=host,
                    path=path,
                    action=("block" if level == "R1" else "log"),
                    level=level,
                )
            except Exception as e:
                log.warning("utiq event store failed: %s", e)

        if level == "R1":
            # Short-circuit the flow : return a 451 (Unavailable For
            # Legal Reasons) so the page's JS can detect the block.
            # 451 is more truthful than 404 here — we're refusing to
            # serve operator-tracker content on privacy grounds.
            flow.response = http.Response.make(
                451,
                b'{"error":"blocked_by_secubox","reason":"utiq_tracker"}',
                {"Content-Type": "application/json",
                 "X-SecuBox-Utiq-Block": "R1"},
            )
            log.info("[utiq R1] blocked %s %s for client=%s",
                     host, path, client_ip)


addons = [UtiqDefense()]
