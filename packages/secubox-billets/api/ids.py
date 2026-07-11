# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""ULID generation (Crockford base32, 48-bit ms timestamp + 80-bit randomness).

Self-contained — no external dependency. ULIDs are lexicographically sortable by
creation time, which the public feed's cursor pagination relies on (order by
(created_at, id) with id as the tiebreaker)."""
from __future__ import annotations

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # excludes I L O U
_DECODE = {c: i for i, c in enumerate(_CROCKFORD)}


def _encode(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        value, rem = divmod(value, 32)
        out.append(_CROCKFORD[rem])
    return "".join(reversed(out))


def new_ulid(ts_ms: int | None = None, randomness: bytes | None = None) -> str:
    """Return a 26-char ULID. `ts_ms`/`randomness` are injectable for tests."""
    ts = int(time.time() * 1000) if ts_ms is None else ts_ms
    if ts < 0 or ts >= (1 << 48):
        raise ValueError("timestamp out of 48-bit range")
    rnd = os.urandom(10) if randomness is None else randomness
    if len(rnd) != 10:
        raise ValueError("randomness must be 10 bytes (80 bits)")
    return _encode(ts, 10) + _encode(int.from_bytes(rnd, "big"), 16)


def ulid_timestamp_ms(ulid: str) -> int:
    """Extract the millisecond timestamp encoded in a ULID's first 10 chars."""
    if len(ulid) != 26:
        raise ValueError("invalid ULID length")
    value = 0
    for ch in ulid[:10].upper():
        if ch not in _DECODE:
            raise ValueError(f"invalid ULID char: {ch!r}")
        value = value * 32 + _DECODE[ch]
    return value


def is_ulid(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 26:
        return False
    return all(c in _DECODE for c in value.upper())
