# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — kbin (R3 toolbox tunnel persona) presence
collector (Project B, #820, Task 4).

`collect_kbin(store, *, personas_source, report_token_source)` turns the R3
toolbox's wg-persona identities into `kbin:<mac_hash>` rows in a
`PresenceStore`. The simplest signal already on disk for "which personas
are active" is the sbxmitm media-catch discovery log
(`/run/secubox/media-catch.jsonl`, see
`common/secubox_core/media_catch.py`) — each line is one mediaRecord
carrying `client`, the wg-persona `mac_hash` the R3 kbin report is also
keyed on:

    {"ts":…, "client":"<mac_hash>", "host":…, "url":…,
     "kind":"manifest|video|audio|page", "ctype":"video/mp4", "bytes":123}

Bounded tail-read: reuses `presence.wan`'s private `_tail_lines` helper
(the same seek-from-end-then-drop-partial-first-line pattern ported from
`common/secubox_core/media_catch.py`'s `_tail_lines`) rather than
duplicating it a third time in this package.

`identity` is the `mac_hash` itself — never a raw device identity — per
the plan's privacy constraint ("kbin uses `mac_hash`, not raw identity").
`report_token_source` is an OPTIONAL lookup (a `dict[mac_hash] -> token`
or a `callable(mac_hash) -> token | None`) for the toolbox kbin report
token, when the caller has one available; when absent (the default), no
`report_token` is stored and the webui can deep-link using the `mac_hash`
itself (the report is keyed on it directly).

Fail-safe throughout: a missing/unreadable personas source, malformed
JSON lines, a raising `report_token_source`, or a single bad `upsert`
degrade quietly — `collect_kbin` itself NEVER raises, returning 0 when
nothing could be collected.

Pure stdlib + `.store` (`pid`) + `.wan` (`_tail_lines`, reused). No I/O at
import time — only `collect_kbin()` touches the filesystem.
"""
from __future__ import annotations

import json
import time

from .store import pid
from .wan import _tail_lines

DEFAULT_PERSONAS_SOURCE = "/run/secubox/media-catch.jsonl"
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_LINES = 5000


def _read_persona_records(
    path: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
) -> list:
    """Bounded tail-read + JSON-parse the personas source into dicts.

    Factored out so tests can point it at a fixture file directly (or
    monkeypatch it) without touching the real `/run/secubox` path.
    Fail-safe: a missing/unreadable file yields `[]` (via `_tail_lines`);
    malformed/non-dict lines are skipped.
    """
    records = []
    for line in _tail_lines(path, max_bytes, max_lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return records


def _to_epoch(v):
    """Best-effort conversion of a media-catch `ts` value to an int epoch."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str):
        try:
            return int(float(v))
        except ValueError:
            return None
    return None


def _resolve_report_token(report_token_source, mac_hash: str):
    """Best-effort kbin report token lookup. Never raises.

    Accepts either a `dict[mac_hash] -> token` or a
    `callable(mac_hash) -> token | None`; any other/absent source (or a
    raising callable/mapping) yields `None`.
    """
    if not report_token_source:
        return None
    try:
        if callable(report_token_source):
            return report_token_source(mac_hash)
        return report_token_source.get(mac_hash)
    except Exception:
        return None


def collect_kbin(
    store,
    *,
    personas_source: str = DEFAULT_PERSONAS_SOURCE,
    report_token_source=None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
) -> int:
    """Collect R3 toolbox kbin personas into `kbin:<mac_hash>` presences.

    Returns the number of distinct persona `mac_hash`es upserted. Fail-safe:
    a missing/unreadable personas source, malformed lines, or any other
    error never raises out of this function — worst case it returns 0.
    """
    try:
        records = _read_persona_records(personas_source, max_bytes, max_lines)
    except Exception:
        return 0

    if not records:
        return 0

    # Dedup per distinct mac_hash — last occurrence in tail order (most
    # recent sighting) wins the row's `last_seen`, mirroring `wan.py`'s
    # per-collect-cycle dedup choice.
    by_hash: dict = {}
    for rec in records:
        client = rec.get("client")
        if not client or not isinstance(client, str):
            continue
        by_hash[client] = rec

    now = int(time.time())
    count = 0
    for mac_hash, rec in by_hash.items():
        last_seen = _to_epoch(rec.get("ts")) or now

        token = _resolve_report_token(report_token_source, mac_hash)
        extra = {"report_token": token} if token else {}

        try:
            store.upsert({
                "id": pid("kbin", mac_hash),
                "plane": "kbin",
                "identity": mac_hash,
                "provenance": "tunnel",
                "client_type": "persona",
                "last_seen": last_seen,
                "extra": json.dumps(extra),
            })
        except Exception:
            # Fail-safe: a single bad upsert must not abort the collect.
            continue
        count += 1

    return count
