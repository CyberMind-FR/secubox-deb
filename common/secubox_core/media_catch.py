# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: media-catch aggregator

Shared reader for the sbxmitm media-catch discovery log
(/run/secubox/media-catch.jsonl). Each line is one mediaRecord written by the
toolbox-ng MITM workers in R4/analyst mode:

    {"ts":…, "client":"<mac_hash>", "host":…, "url":…,
     "kind":"manifest|video|audio|page", "ctype":"video/mp4", "bytes":123}

`client` is the same wg-persona mac_hash the report keys on, so aggregate() can
produce a per-device (`me`) view alongside the board-wide (`all`) view. Pure /
stdlib only — no FastAPI, no I/O beyond reading the file. Fail-empty: a missing
file, empty file, or corrupt lines never raise.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

MEDIA_CATCH_PATH = "/run/secubox/media-catch.jsonl"

_KIND_EMOJI = {"video": "📺", "audio": "🎵", "manifest": "🎞️", "page": "▶️"}


def _tail_lines(path: Path, max_lines: int) -> list[str]:
    """Return up to the last `max_lines` decoded lines, best-effort."""
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    parts = raw.splitlines()
    if len(parts) > max_lines:
        parts = parts[-max_lines:]
    out: list[str] = []
    for b in parts:
        try:
            out.append(b.decode("utf-8"))
        except UnicodeDecodeError:
            continue
    return out


def _empty_view() -> dict:
    return {"present": False, "flows": 0, "bytes": 0,
            "kinds": [], "ctypes": [], "top_hosts": []}


def _summarize(records: list[dict]) -> dict:
    if not records:
        return _empty_view()
    kinds: Counter = Counter()
    ctypes: Counter = Counter()
    host_bytes: dict = defaultdict(int)
    host_kind: dict = {}
    total_bytes = 0
    for r in records:
        try:
            kind = r.get("kind") or "?"
            kinds[kind] += 1
            ct = r.get("ctype") or ""
            if ct:
                ctypes[ct] += 1
            b = int(r.get("bytes") or 0)
            total_bytes += b
            host = r.get("host") or "?"
            host_bytes[host] += b
            host_kind.setdefault(host, kind)
        except (ValueError, TypeError):
            # Skip malformed-field record; continue with next
            continue
    kinds_out = [{"label": k, "emoji": _KIND_EMOJI.get(k, "🎬"), "count": c}
                 for k, c in kinds.most_common()]
    ctypes_out = [{"label": k, "emoji": "🏷️", "count": c}
                  for k, c in ctypes.most_common(8)]
    top_hosts = sorted(
        ({"host": h, "kind": host_kind.get(h, "?"), "bytes": b}
         for h, b in host_bytes.items()),
        key=lambda x: x["bytes"], reverse=True)[:10]
    return {"present": True, "flows": len(records), "bytes": total_bytes,
            "kinds": kinds_out, "ctypes": ctypes_out, "top_hosts": top_hosts}


def aggregate(path: str = MEDIA_CATCH_PATH, mac_hash: str | None = None,
              max_lines: int = 50_000) -> dict:
    """Aggregate the media-catch log into {all, me} views. Fail-empty."""
    p = Path(path)
    all_records: list[dict] = []
    me_records: list[dict] = []
    for line in _tail_lines(p, max_lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        all_records.append(rec)
        if mac_hash and rec.get("client") == mac_hash:
            me_records.append(rec)
    return {
        "all": _summarize(all_records),
        "me": _summarize(me_records) if mac_hash else _empty_view(),
    }
