# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Runtime ASGI entrypoint: `uvicorn api.asgi:app`.

A lifespan opens the WAL SQLite connection (running migrations) once at startup
and closes it (plus the outbound HTTP client) on shutdown. The DB path, signing
secret, and revision dir come from the environment (see README)."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from . import db, repo
from .main import create_app


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _balayer(conn, pas: float = 30.0) -> None:
    """Balayage des billets éphémères (#2268) : archive ceux échus, supprime ceux échus depuis plus de 24 h. Le fil, lui, les exclut déjà à la lecture."""
    while True:
        try:
            await repo.expirer(conn)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — un balayage raté ne doit jamais arrêter le service
            pass
        await asyncio.sleep(pas)


@asynccontextmanager
async def lifespan(app):
    conn = await db.connect(now=_now())
    app.state.conn = conn
    balayage = asyncio.create_task(_balayer(conn))
    try:
        yield
    finally:
        balayage.cancel()
        await conn.close()
        client = getattr(app.state, "http_client", None)
        if client is not None:
            await client.aclose()


app = create_app(conn=None, lifespan=lifespan)
