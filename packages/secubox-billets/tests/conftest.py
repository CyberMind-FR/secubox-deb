# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import sys
from pathlib import Path

import pytest_asyncio

# Make `api` importable as a top-level package (mirrors the module's runtime
# layout under /usr/lib/secubox/billets).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import db as _db  # noqa: E402

_FIXED_NOW = "2026-07-11T12:00:00Z"


@pytest_asyncio.fixture
async def conn():
    """A migrated, in-memory WAL database on a single connection."""
    c = await _db.connect(":memory:", now=_FIXED_NOW)
    try:
        yield c
    finally:
        await c.close()
