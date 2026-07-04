# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.exclusion — cert-pinned / MITM-bypassed hosts.

Single source of truth is the toolbox's own MITM-exclusion lists, so a host the
toolbox refuses to intercept (cert-pinned / E2E apps, pinned APIs) is also
refused a Tor hidden service — you must never anonymously re-expose an endpoint
that clients pin. The list is read live from the same files the toolbox uses,
so operator edits (Filtres MITM webui) and autolearn feed the Tor gate too:

  * MITM ignore_hosts bypass (REGEX, one per line):
      seed    /usr/lib/secubox/toolbox/conf/mitm-bypass-seed.conf   (package)
      static  /var/lib/secubox/toolbox/mitm-bypass.conf             (webui add/remove)
      learned /var/lib/secubox/toolbox/mitm-bypass-dynamic.conf     (autolearn)
  * TLS SNI splice (host SUFFIX, one per line):
      seed    /usr/lib/secubox/toolbox/conf/tls-splice-seed.conf    (package)
      learned /var/lib/secubox/toolbox/splice-learned.txt           (autolearn)

Read-only + best-effort: an unreadable/missing list never raises — it just
contributes nothing (fail-open on availability, never fail-closed on a missing
toolbox). Matching itself is fail-safe: a host that matches ANY list is excluded.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Set, Tuple

_BYPASS_FILES = (
    os.environ.get("SECUBOX_BYPASS_SEED", "/usr/lib/secubox/toolbox/conf/mitm-bypass-seed.conf"),
    os.environ.get("SECUBOX_BYPASS_STATIC", "/var/lib/secubox/toolbox/mitm-bypass.conf"),
    os.environ.get("SECUBOX_BYPASS_DYNAMIC", "/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf"),
)
_SPLICE_FILES = (
    os.environ.get("SECUBOX_SPLICE_SEED", "/usr/lib/secubox/toolbox/conf/tls-splice-seed.conf"),
    os.environ.get("SECUBOX_SPLICE_LEARNED", "/var/lib/secubox/toolbox/splice-learned.txt"),
)


def _lines(path: str) -> List[str]:
    """Non-comment, non-empty stripped lines; missing/unreadable → []."""
    try:
        out = []
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                out.append(line)
        return out
    except OSError:
        return []


def _load_bypass_regex() -> List[re.Pattern]:
    pats: List[re.Pattern] = []
    for f in _BYPASS_FILES:
        for line in _lines(f):
            try:
                pats.append(re.compile(line, re.IGNORECASE))
            except re.error:
                continue  # a malformed operator regex must not break the gate
    return pats


def _load_splice_suffixes() -> Set[str]:
    out: Set[str] = set()
    for f in _SPLICE_FILES:
        for line in _lines(f):
            out.add(line.lower().strip("."))
    return out


def _suffix_match(host: str, suffixes: Set[str]) -> bool:
    h = (host or "").lower().strip(".")
    if not h or not suffixes:
        return False
    if h in suffixes:
        return True
    return any(h.endswith("." + s) for s in suffixes)


def exclusion_reason(host: str) -> Tuple[bool, str]:
    """(excluded, reason). reason names which list matched, for audit + UI."""
    h = (host or "").strip()
    if not h:
        return (False, "")
    for pat in _load_bypass_regex():
        if pat.fullmatch(h):
            return (True, f"MITM-bypass (cert-pinned): {pat.pattern}")
    suf = _load_splice_suffixes()
    if _suffix_match(h, suf):
        return (True, "TLS-splice (cert-pinned API)")
    return (False, "")


def is_excluded(host: str) -> bool:
    return exclusion_reason(host)[0]
