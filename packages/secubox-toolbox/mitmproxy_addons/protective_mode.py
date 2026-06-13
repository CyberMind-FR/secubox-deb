# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Phase 14 sketch (#560, refs #525/#514/#500) — Toolbox PROTECTIVE MODE :
# tracker alerting + active spoofer.
#
# Doctrine (CM-WALL) : active interference is OPT-IN, DEFAULT OFF, LOGGED,
# REVERSIBLE — mirrors Phase 13.D escalate + Phase 8 utiq_defense. It only
# ever touches classified **3rd-party tracker** hosts ; 1st-party traffic is
# never modified, so pages keep working.
#
# Levels — env `SECUBOX_PROTECTIVE_MODE` (default `off`) :
#   off    passthrough (no-op).
#   alert  detect + audit-log + count tracker flows. No modification.
#   spoof  alert + neutralise on tracker hosts only :
#            - strip operator-grade / tracking request headers
#              (MSISDN, x-acr, x-up-calling-line-id, x-wap-*, forwarded IPs)
#            - drop the Cookie header sent to the tracker (kills cookie reuse)
#            - assert DNT:1 + Sec-GPC:1
#          Every spoof action is appended to /var/log/secubox/audit.log.
from __future__ import annotations

import logging
import os
import re
import time

from mitmproxy import http

log = logging.getLogger("secubox.toolbox.protective")

_AUDIT = "/var/log/secubox/audit.log"
_STATS = "/run/secubox/protective.json"

# 3rd-party tracker hosts (mirror of inject_banner's _TRACKER_PATTERNS).
_TRACKER = re.compile(
    r"(?:^|\.)(?:"
    r"doubleclick|googlesyndication|googleadservices|googletagmanager|"
    r"google-analytics|googletagservices|adservice\.google|"
    r"facebook\.com/tr|connect\.facebook\.net|facebook\.net|"
    r"scorecardresearch|chartbeat|hotjar|mixpanel|amplitude|"
    r"segment\.com|segment\.io|criteo|adnxs|rubiconproject|"
    r"taboola|outbrain|smartadserver|optimizely|fullstory|"
    r"newrelic|datadog|sentry|amazon-adsystem|adsrvr|adform|"
    r"yieldlove|moatads|adsystem|adserver|liveramp|bluekai|"
    r"krxd|demdex|agkn|tapad|exelator|utiq"
    r")",
    re.IGNORECASE,
)

# Operator-grade / tracking request headers stripped in spoof mode.
_STRIP = (
    "msisdn", "x-msisdn", "x-up-calling-line-id", "x-up-subno",
    "x-nokia-msisdn", "x-acr", "x-vf-acr", "x-amobee-1", "x-amobee-2",
    "tm-user-id", "x-wap-profile", "x-wap-msisdn", "x-network-info",
    "x-forwarded-for", "forwarded", "x-real-ip", "via",
)

_counts = {"alerts": 0, "spoofs": 0, "since": int(time.time())}
_last_flush = 0.0


def _level() -> str:
    v = (os.environ.get("SECUBOX_PROTECTIVE_MODE") or "off").strip().lower()
    return v if v in ("off", "alert", "spoof") else "off"


def _is_tracker(host: str) -> bool:
    return bool(host) and bool(_TRACKER.search(host))


def _audit(action: str, host: str, detail: str) -> None:
    try:
        line = "%s protective %s host=%s %s\n" % (
            time.strftime("%Y-%m-%dT%H:%M:%S%z"), action, host, detail)
        with open(_AUDIT, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass  # audit is best-effort ; never break the flow


def _flush_stats(force: bool = False) -> None:
    global _last_flush
    now = time.time()
    if not force and (now - _last_flush) < 5:
        return
    _last_flush = now
    try:
        import json
        os.makedirs(os.path.dirname(_STATS), exist_ok=True)
        with open(_STATS, "w", encoding="utf-8") as f:
            json.dump({**_counts, "mode": _level(), "updated": int(now)}, f)
    except Exception:
        pass


class ProtectiveMode:
    """Alert on, and (spoof level) actively neutralise, tracker flows."""

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        level = _level()
        if level == "off":
            return
        host = flow.request.pretty_host or ""
        if not _is_tracker(host):
            return

        _counts["alerts"] += 1
        if level == "alert":
            _audit("alert", host, "path=%s" % (flow.request.path or "")[:120])
            _flush_stats()
            return

        # ── spoof ──
        stripped = []
        for h in _STRIP:
            if h in flow.request.headers:
                del flow.request.headers[h]
                stripped.append(h)
        # kill cookie reuse to the tracker
        had_cookie = "cookie" in flow.request.headers
        if had_cookie:
            del flow.request.headers["cookie"]
        # strip a referer that would leak the 1st-party page to the tracker
        if "referer" in flow.request.headers:
            del flow.request.headers["referer"]
            stripped.append("referer")
        # assert the opt-out signals
        flow.request.headers["DNT"] = "1"
        flow.request.headers["Sec-GPC"] = "1"
        flow.request.headers["X-SecuBox-Protected"] = "spoof"

        _counts["spoofs"] += 1
        _audit("spoof", host, "stripped=%s cookie=%s" % (
            ",".join(stripped) or "-", "drop" if had_cookie else "-"))
        _flush_stats()
        log.info("[protective spoof] %s stripped=%d cookie=%s",
                 host, len(stripped), had_cookie)


addons = [ProtectiveMode()]
