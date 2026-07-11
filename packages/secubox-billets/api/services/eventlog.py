# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Append-only, hash-chained event log (a project invariant).

Every security-relevant action (publish, edit, delete, comment moderation,
login) appends one row whose `hash` = BLAKE2b(prev_hash || canonical(event)).
Each row carries the previous row's hash, so any tampering with an earlier row
(or a deletion/reorder) is detectable by `verify_chain`. Digest size is 32 bytes
(64 hex chars); the genesis `prev_hash` is 64 zeros."""
from __future__ import annotations

import hashlib
import json
from typing import Any

import aiosqlite

GENESIS = "0" * 64
_DIGEST_SIZE = 32

EVENT_TYPES = frozenset({
    "billet.published", "billet.edited", "billet.deleted",
    "comment.approved", "comment.rejected", "comment.created",
    "author.login", "author.login_failed",
})


def _canonical(event_type: str, ts: str, payload: dict[str, Any]) -> bytes:
    """Deterministic bytes for hashing: type, timestamp, and a sorted-key,
    separator-tight JSON of the payload. Stable across processes/versions."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{event_type}\x1f{ts}\x1f{body}".encode("utf-8")


def _row_hash(prev_hash: str, event_type: str, ts: str, payload: dict[str, Any]) -> str:
    h = hashlib.blake2b(digest_size=_DIGEST_SIZE)
    h.update(prev_hash.encode("ascii"))
    h.update(b"\x1e")
    h.update(_canonical(event_type, ts, payload))
    return h.hexdigest()


async def _last_hash(conn: aiosqlite.Connection) -> str:
    async with conn.execute("SELECT hash FROM event_log ORDER BY id DESC LIMIT 1") as cur:
        row = await cur.fetchone()
    return row[0] if row else GENESIS


async def append_event(
    conn: aiosqlite.Connection,
    event_type: str,
    payload: dict[str, Any],
    *,
    ts: str,
) -> str:
    """Append one event and return its hash. Caller supplies the RFC3339 `ts`
    (so the timestamp source stays testable/deterministic)."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type: {event_type!r}")
    prev = await _last_hash(conn)
    row_hash = _row_hash(prev, event_type, ts, payload)
    await conn.execute(
        "INSERT INTO event_log(ts, event_type, payload, prev_hash, hash) "
        "VALUES (?,?,?,?,?)",
        (ts, event_type, json.dumps(payload, sort_keys=True, separators=(",", ":")),
         prev, row_hash),
    )
    await conn.commit()
    return row_hash


async def verify_chain(conn: aiosqlite.Connection) -> bool:
    """Recompute the whole chain; return True iff every link is intact."""
    prev = GENESIS
    async with conn.execute(
        "SELECT event_type, ts, payload, prev_hash, hash FROM event_log ORDER BY id ASC"
    ) as cur:
        rows = await cur.fetchall()
    for event_type, ts, payload_json, prev_hash, stored_hash in rows:
        if prev_hash != prev:
            return False
        payload = json.loads(payload_json)
        if _row_hash(prev, event_type, ts, payload) != stored_hash:
            return False
        prev = stored_hash
    return True
