# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import pytest

from api.services import eventlog


async def test_chain_verifies(conn):
    await eventlog.append_event(conn, "billet.published", {"id": "A"}, ts="2026-07-11T12:00:01Z")
    await eventlog.append_event(conn, "comment.approved", {"id": "C1"}, ts="2026-07-11T12:00:02Z")
    await eventlog.append_event(conn, "author.login", {"user": "gk"}, ts="2026-07-11T12:00:03Z")
    assert await eventlog.verify_chain(conn) is True


async def test_first_row_links_to_genesis(conn):
    h = await eventlog.append_event(conn, "author.login", {"user": "gk"}, ts="2026-07-11T12:00:01Z")
    async with conn.execute("SELECT prev_hash, hash FROM event_log ORDER BY id") as cur:
        row = await cur.fetchone()
    assert row[0] == eventlog.GENESIS
    assert row[1] == h


async def test_tampering_breaks_chain(conn):
    await eventlog.append_event(conn, "billet.published", {"id": "A"}, ts="2026-07-11T12:00:01Z")
    await eventlog.append_event(conn, "billet.edited", {"id": "A"}, ts="2026-07-11T12:00:02Z")
    # Mutate an earlier row's payload in place (an attacker editing history).
    await conn.execute("UPDATE event_log SET payload='{\"id\":\"HACKED\"}' WHERE id=1")
    await conn.commit()
    assert await eventlog.verify_chain(conn) is False


async def test_unknown_event_type_rejected(conn):
    with pytest.raises(ValueError):
        await eventlog.append_event(conn, "nope.invalid", {}, ts="2026-07-11T12:00:01Z")
