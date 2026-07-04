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
    """Non-comment, non-empty stripped lines; missing/unreadable/undecodable → [].

    Fail-open on availability: a missing toolbox, a permission error, OR a
    non-UTF-8 byte (corruption / bad operator paste) must never raise into the
    request path — the file simply contributes nothing. UnicodeDecodeError is a
    ValueError, not an OSError, so both are caught.
    """
    try:
        out = []
        for raw in Path(path).read_text(encoding="utf-8", errors="strict").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                out.append(line)
        return out
    except (OSError, ValueError):
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


# mtime-keyed cache: recompiling every bypass regex on each Tor request would
# add avoidable work on the shared aggregator loop. Reload only when a list file
# changes (autolearn append, webui edit) — cheap stat() vs full recompile.
_cache: dict = {"key": None, "regex": [], "suffix": set()}


def _list_key():
    key = []
    for f in _BYPASS_FILES + _SPLICE_FILES:
        try:
            key.append((f, Path(f).stat().st_mtime))
        except OSError:
            key.append((f, None))
    return tuple(key)


def _loaded():
    key = _list_key()
    if key != _cache["key"]:
        _cache["regex"] = _load_bypass_regex()
        _cache["suffix"] = _load_splice_suffixes()
        _cache["key"] = key
    return _cache["regex"], _cache["suffix"]


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
    regex, suffix = _loaded()
    for pat in regex:
        if pat.fullmatch(h):
            return (True, f"MITM-bypass (cert-pinned): {pat.pattern}")
    if _suffix_match(h, suffix):
        return (True, "TLS-splice (cert-pinned API)")
    return (False, "")


def is_excluded(host: str) -> bool:
    return exclusion_reason(host)[0]
