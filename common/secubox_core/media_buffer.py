# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: media-buffer metatag reader

Shared reader for the sbxmitm media-buffer metatag log
(/data/secubox/media-buffer/media-buffer.jsonl). Each line is one metatag
record appended by the toolbox-ng MITM workers (Task 1) or by the janitor
(Task 3) when it evicts the backing bytes:

    {"id","session_id","first_ts","last_ts","mac_hash","host","url",
     "direction","kind","ctype","bytes","segments","truncated",
     "buffer_ref","expired"}

The log is append-only, so a given `id` can appear on multiple lines — the
janitor "flips" a record on eviction by appending a fresh line with
`expired:true, buffer_ref:null` rather than rewriting history. Readers MUST
dedup by `id`, last line wins, so the eviction flip is always honored.

Pure stdlib only — no FastAPI, no I/O beyond reading the file. Fail-empty: a
missing file, empty file, or corrupt/partial lines never raise.

`max_bytes` bounds how much of the file is actually read off disk (a bounded
tail read), while `max_lines` bounds how many records are kept/processed
after that read — the two are independent caps.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

MEDIA_BUFFER_PATH = "/data/secubox/media-buffer/media-buffer.jsonl"


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


def _deduped_records(path: str, max_lines: int,
                      max_bytes: int = 16 * 1024 * 1024) -> dict:
    """Parse the tail of the JSONL log into {id: record}, last line wins.

    Records missing an `id` are skipped (can't be deduped/looked up safely).
    Fail-empty: any file/parse error yields an empty dict, never raises.
    """
    p = Path(path)
    by_id: dict = {}
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
        rec_id = rec.get("id")
        if not rec_id:
            continue
        by_id[rec_id] = rec  # later lines overwrite — last-writer-wins
    return by_id


def read_records(path: str = MEDIA_BUFFER_PATH, mac_hash: str | None = None,
                  max_lines: int = 2000,
                  max_bytes: int = 16 * 1024 * 1024) -> list[dict]:
    """Return deduped metatag records, newest-first. Fail-empty."""
    by_id = _deduped_records(path, max_lines, max_bytes=max_bytes)
    records = list(by_id.values())
    if mac_hash:
        records = [r for r in records if r.get("mac_hash") == mac_hash]
    try:
        records.sort(key=lambda r: r.get("first_ts") or 0, reverse=True)
    except TypeError:
        # Defensive: a malformed first_ts type shouldn't blow up the caller.
        pass
    return records


def record_by_id(rec_id: str, path: str = MEDIA_BUFFER_PATH,
                  max_lines: int = 2000,
                  max_bytes: int = 16 * 1024 * 1024) -> dict | None:
    """Return the deduped record for `rec_id` (last line wins) or None."""
    if not rec_id:
        return None
    by_id = _deduped_records(path, max_lines, max_bytes=max_bytes)
    return by_id.get(rec_id)
