# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Seed a handful of published billets for local development / first boot."""
from __future__ import annotations

import aiosqlite

from . import repo
from .ids import new_ulid
from .models import BilletIn

_SAMPLES = [
    ("Bienvenue sur **billets** — un micro-blog *gateway* auto-hébergé.", True),
    ("On peut mettre des [liens](https://secubox.in) et des listes :\n\n- un\n- deux\n- trois", True),
    ("> Une citation vaut mille billets.\n\nEt du `code` en ligne.", True),
    ("Ceci est un **brouillon** qui ne doit pas apparaître au public.", False),
]


async def seed_billets(conn: aiosqlite.Connection, *, base_ts: str = "2026-07-11T12:00:0") -> list[str]:
    ids: list[str] = []
    for i, (body, publish) in enumerate(_SAMPLES):
        ulid = new_ulid(ts_ms=1_700_000_000_000 + i, randomness=bytes([i]) * 10)
        now = f"{base_ts}{i}Z"
        ids.append(await repo.create_billet(conn, BilletIn(body=body, publish=publish),
                                            now=now, ulid=ulid))
    return ids
