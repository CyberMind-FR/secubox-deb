# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: toolbox :: SNI-splice classifier (#649).

Pure helpers deciding, from the TLS SNI alone, whether a flow is a pure-asset
flow we can splice (raw passthrough, no MITM). Seed ∪ learned, minus a never-set
(trackers we block/poison, fortknox sites). Suffix match so CDN shards match.
"""
from __future__ import annotations

import os
from typing import Set


def _load_lines(path: str) -> Set[str]:
    out: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.split("#", 1)[0].strip().lower()
                if line:
                    out.add(line)
    except Exception:
        pass
    return out


def load_splice_seed(path: str) -> Set[str]:
    return _load_lines(path)


def load_learned_splice(path: str) -> Set[str]:
    return _load_lines(path)


def host_matches(host: str, patterns: Set[str]) -> bool:
    """True if host == pattern or host is a subdomain of pattern."""
    h = (host or "").lower().strip(".")
    if not h or not patterns:
        return False
    if h in patterns:
        return True
    for p in patterns:
        if h.endswith("." + p):
            return True
    return False


def should_splice(sni: str, seed: Set[str], learned: Set[str],
                  never: Set[str]) -> bool:
    s = (sni or "").lower().strip(".")
    if not s:
        return False
    if host_matches(s, never):      # never wins (trackers / fortknox)
        return False
    return host_matches(s, seed) or host_matches(s, learned)
