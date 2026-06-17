# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: privacy brain (Anti-Track v2, #633)

Pure-Python policy: classify a host (none / pure / loadbearing), mint a stable
fabricated identity per (client, tracker), and return a per-request verdict
(allow | block | poison | anonymize). No mitmproxy import here — unit-testable.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Optional

# Single source of truth for 3rd-party tracker hosts. protective_mode.py and
# ad_ghost.py import is_tracker() / _TRACKER from here (#633).
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

# Multi-label public suffixes we care about (compact list; full PSL is overkill
# for a LAN privacy tool). Extend as needed.
_MULTI_TLD = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "com.br",
    "co.nz", "co.za", "com.cn", "com.tr",
}

# Learned-trackers list (written by autolearn in plan 2). Each non-comment line
# is a host; lines may carry a trailing reason tag we ignore here.
LEARNED_PATH = "/var/lib/secubox/toolbox/learned-trackers.txt"
# Hosts confirmed beacon-only (safe to hard-block). Written by autolearn (plan
# 2); absent for now → empty set, so everything fails safe to loadbearing.
PURE_PATH = "/var/lib/secubox/toolbox/pure-trackers.txt"

_lists_cache: dict = {"learned": set(), "pure": set(), "mtime": (0.0, 0.0)}


def registrable(host: str) -> str:
    """Best-effort registrable (eTLD+1) domain. Compact multi-TLD table."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or host.replace(".", "").isdigit():
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_TLD:
        return ".".join(parts[-3:])
    return last2


def _load_lists() -> None:
    def _mtime(p: str) -> float:
        try:
            return Path(p).stat().st_mtime
        except OSError:
            return 0.0

    lm, pm = _mtime(LEARNED_PATH), _mtime(PURE_PATH)
    if (lm, pm) == _lists_cache["mtime"]:
        return

    def _read(p: str) -> set:
        out = set()
        try:
            for line in Path(p).read_text(encoding="utf-8").splitlines():
                tok = line.strip().split()
                if tok and not tok[0].startswith("#"):
                    out.add(tok[0].lower())
        except OSError:
            pass
        return out

    _lists_cache["learned"] = _read(LEARNED_PATH)
    _lists_cache["pure"] = _read(PURE_PATH)
    _lists_cache["mtime"] = (lm, pm)


def is_tracker(host: str) -> bool:
    if not host:
        return False
    if _TRACKER.search(host):
        return True
    _load_lists()
    h = host.lower()
    return h in _lists_cache["learned"] or registrable(h) in _lists_cache["learned"]


def classify(host: str, beacon_hint: bool = False) -> str:
    """Return 'none' | 'pure' | 'loadbearing'.

    Fail-safe: a tracker we have NOT confirmed beacon-only is 'loadbearing'
    (poison, never block) so we never break a page.
    """
    if not is_tracker(host):
        return "none"
    _load_lists()
    h = host.lower()
    confirmed_pure = h in _lists_cache["pure"] or registrable(h) in _lists_cache["pure"]
    if confirmed_pure or beacon_hint:
        return "pure"
    return "loadbearing"
