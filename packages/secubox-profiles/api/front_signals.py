# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — signaux du front (last-request, connexions actives)
CyberMind — https://cybermind.fr

LECTURE SEULE. La source réelle (sbxwaf stats JSON à
/var/cache/secubox/waf/stats.json ou nginx stub_status) est injectée via
`reader`. Un champ None = indéterminé, JAMAIS coalescé en 0 (ne pas endormir
sur une sonde muette).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Signal:
    last_request_age: float | None
    active_conns: int | None


def age_from(ts: float | None, now: float) -> float | None:
    """Age in seconds since ts, or None when ts is unknown/not a number."""
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return None
    return now - ts


def vhost_signals(
    *,
    reader: Callable[[], dict[str, dict[str, Any]]],
    now: Callable[[], float] = time.monotonic,
) -> dict[str, Signal]:
    t = now()
    out: dict[str, Signal] = {}
    for vhost, raw in reader().items():
        ts = raw.get("last_request_ts")
        age = age_from(ts, t)
        conns = raw.get("active_conns")
        # isinstance(True, int) is True in Python — guard against a stray
        # bool being mistaken for a connection count.
        safe_conns = conns if isinstance(conns, int) and not isinstance(conns, bool) else None
        out[vhost] = Signal(last_request_age=age, active_conns=safe_conns)
    return out
