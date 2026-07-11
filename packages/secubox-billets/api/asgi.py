# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Runtime ASGI entrypoint: `uvicorn api.asgi:app`.

A lifespan opens the WAL SQLite connection (running migrations) once at startup
and closes it (plus the outbound HTTP client) on shutdown. The DB path, signing
secret, and revision dir come from the environment (see README)."""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from . import db
from .main import create_app


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@asynccontextmanager
async def lifespan(app):
    conn = await db.connect(now=_now())
    app.state.conn = conn
    try:
        yield
    finally:
        await conn.close()
        client = getattr(app.state, "http_client", None)
        if client is not None:
            await client.aclose()


app = create_app(conn=None, lifespan=lifespan)
