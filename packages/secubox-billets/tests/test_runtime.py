# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import importlib


async def test_asgi_lifespan_opens_and_migrates(tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_DB", str(tmp_path / "b.db"))
    monkeypatch.setenv("BILLETS_SECRET", "test-secret")
    monkeypatch.setenv("BILLETS_REVISIONS_DIR", str(tmp_path / "revs"))
    from api import asgi as asgi_mod
    importlib.reload(asgi_mod)
    app = asgi_mod.app
    async with asgi_mod.lifespan(app):
        assert app.state.conn is not None
        async with app.state.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'") as cur:
            names = {r[0] for r in await cur.fetchall()}
        assert {"billet", "comment", "reaction", "author", "event_log"} <= names


async def test_manage_create_author(tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_DB", str(tmp_path / "m.db"))
    monkeypatch.setenv("BILLETS_SECRET", "test-secret")
    from api import manage
    assert await manage._create_author("gk", "supersecret123") == 0
    assert await manage._create_author("gk", "supersecret123") == 1  # duplicate
    assert await manage._set_password("gk", "another-secret-9") == 0
    assert await manage._set_password("ghost", "another-secret-9") == 1


async def test_manage_seed(tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_DB", str(tmp_path / "s.db"))
    from api import manage, db
    assert await manage._seed() == 0
    conn = await db.connect(now="2026-07-11T12:00:00Z")
    async with conn.execute("SELECT COUNT(*) FROM billet WHERE status='published'") as cur:
        assert (await cur.fetchone())[0] >= 1
    await conn.close()
