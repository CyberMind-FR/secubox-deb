# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: podcaster store retry/recovery tests
CyberMind — https://cybermind.fr

Covers the #853 additions: the `attempts` column migration, orphan recovery
(`requeue_stuck`) and the auto-retry counter (`bump_attempts`).
"""
import importlib

import pytest


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("PODCASTER_DB", str(tmp_path / "p.db"))
    import api.store as st
    importlib.reload(st)
    st.DB_PATH = tmp_path / "p.db"
    st.init()
    return st


def _add_episode(st, state="new"):
    fid = st.add_feed("http://x/f.xml", {"title": "F"})
    with st._conn() as c:
        cur = c.execute(
            "INSERT INTO episodes(feed_id,guid,title,enclosure,state) VALUES(?,?,?,?,?)",
            (fid, "g%d" % id(state), "ep", "http://x/a.mp3", state),
        )
        return cur.lastrowid


def test_attempts_column_present(store):
    cols = {r[1] for r in store._conn().execute("PRAGMA table_info(episodes)")}
    assert "attempts" in cols


def test_migration_is_idempotent_on_legacy_db(store):
    # Drop the column-bearing table and recreate the PRE-attempts schema, then
    # prove init() adds the column without error and re-running is a no-op.
    with store._conn() as c:
        c.execute("DROP TABLE episodes")
        c.execute(
            "CREATE TABLE episodes(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "feed_id INTEGER, guid TEXT, title TEXT, description TEXT, "
            "pubdate INTEGER DEFAULT 0, enclosure TEXT, mime TEXT, "
            "bytes INTEGER DEFAULT 0, duration TEXT, local_path TEXT, "
            "state TEXT DEFAULT 'new', progress INTEGER DEFAULT 0, error TEXT, "
            "UNIQUE(feed_id, guid))"
        )
    store.init()
    store.init()  # second call must not raise "duplicate column"
    cols = {r[1] for r in store._conn().execute("PRAGMA table_info(episodes)")}
    assert "attempts" in cols


def test_requeue_stuck_resets_and_returns_ids(store):
    a = _add_episode(store, "downloading")
    b = _add_episode(store, "queued")
    done = _add_episode(store, "done")
    ids = store.requeue_stuck()
    assert set(ids) == {a, b}
    assert store.get_episode(a)["state"] == "queued"
    assert store.get_episode(a)["progress"] == 0
    assert store.get_episode(done)["state"] == "done"  # untouched


def test_bump_attempts_increments(store):
    ep = _add_episode(store, "queued")
    assert store.bump_attempts(ep) == 1
    assert store.bump_attempts(ep) == 2
    assert store.get_episode(ep)["attempts"] == 2
