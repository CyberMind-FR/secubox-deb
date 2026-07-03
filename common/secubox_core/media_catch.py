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

`max_bytes` bounds how much of the file is actually read off disk (a bounded
tail read), while `max_lines` bounds how many records are kept/processed after
that read — the two are independent caps.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path

MEDIA_CATCH_PATH = "/run/secubox/media-catch.jsonl"

_KIND_EMOJI = {"video": "📺", "audio": "🎵", "manifest": "🎞️", "page": "▶️"}


def _tail_lines(path: Path, max_lines: int,
                 max_bytes: int = 16 * 1024 * 1024) -> list[str]:
    """Return up to the last `max_lines` decoded lines, best-effort.

    Only the tail `max_bytes` of the file are ever read off disk — on a busy
    board the log can grow large, so this bounds memory/IO regardless of
    `max_lines`. If the seek lands mid-line, the (possibly partial) first
    line of the read is dropped.
    """
    try:
        with path.open("rb") as f:
            size = f.seek(0, os.SEEK_END)
            if size > max_bytes:
                f.seek(size - max_bytes)
                raw = f.read()
                parts = raw.splitlines()
                # Drop the first (possibly partial) line from the mid-file seek.
                parts = parts[1:]
            else:
                f.seek(0)
                raw = f.read()
                parts = raw.splitlines()
    except OSError:
        return []
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
              max_lines: int = 50_000,
              max_bytes: int = 16 * 1024 * 1024) -> dict:
    """Aggregate the media-catch log into {all, me} views. Fail-empty."""
    p = Path(path)
    all_records: list[dict] = []
    me_records: list[dict] = []
    for line in _tail_lines(p, max_lines, max_bytes=max_bytes):
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
