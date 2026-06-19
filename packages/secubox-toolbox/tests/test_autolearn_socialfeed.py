# tests/test_autolearn_socialfeed.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#662 — cross-site-reuse promotion: a tracker_domain seen on >= N distinct
src_site across recent social_edges is a behaviourally-confirmed cross-site
tracker and gets promoted into learned-trackers.txt. Allowlist + self guard
reused from _ad_feed; merges (never overwrites)."""
import sqlite3
import importlib.util
import pathlib
import time


def _load_autolearn():
    p = pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-autolearn"
    spec = importlib.util.spec_from_loader("autolearn", loader=None)
    mod = importlib.util.module_from_spec(spec)
    exec(compile(p.read_text(), str(p), "exec"), mod.__dict__)
    return mod


def _mk_db(db):
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE social_edges("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,"
        " client_mac_hash TEXT, src_site TEXT NOT NULL,"
        " tracker_domain TEXT NOT NULL, cookie_id_hash TEXT,"
        " ja4_hash TEXT, consent_state TEXT DEFAULT 'none_seen');")
    return con


def test_social_feed_promotes_cross_site_tracker(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    con = _mk_db(db)
    now = int(time.time())
    rows = [
        # tracker.io: 3 distinct src_sites (>= SOCIAL_MIN_SITES=3) → promote
        (now, "m1", "cnn.com", "tracker.io"),
        (now, "m1", "bbc.com", "tracker.io"),
        (now, "m2", "lemonde.fr", "tracker.io"),
        # twosite.net: only 2 distinct sites → NOT promoted
        (now, "m1", "cnn.com", "twosite.net"),
        (now, "m1", "bbc.com", "twosite.net"),
        # safe.cdn.net: 3 sites but ALLOWLISTED → excluded
        (now, "m1", "a.com", "safe.cdn.net"),
        (now, "m1", "b.com", "safe.cdn.net"),
        (now, "m1", "c.com", "safe.cdn.net"),
        # secubox.in: 3 sites but SELF domain → excluded
        (now, "m1", "a.com", "secubox.in"),
        (now, "m1", "b.com", "secubox.in"),
        (now, "m1", "c.com", "secubox.in"),
        # stale.io: 3 sites but OUTSIDE the recent window → excluded
        (now - 999999, "m1", "a.com", "stale.io"),
        (now - 999999, "m1", "b.com", "stale.io"),
        (now - 999999, "m1", "c.com", "stale.io"),
    ]
    con.executemany(
        "INSERT INTO social_edges(ts,client_mac_hash,src_site,tracker_domain) "
        "VALUES(?,?,?,?)", rows)
    con.commit()
    con.close()

    allow = tmp_path / "ad-allowlist.txt"
    allow.write_text("safe.cdn.net\n")
    out = tmp_path / "learned-trackers.txt"
    out.write_text("preexisting.tracker.com\n")

    monkeypatch.setenv("SECUBOX_AUTOLEARN_DB", str(db))
    monkeypatch.setenv("SECUBOX_AUTOLEARN_OUT", str(out))
    monkeypatch.setenv("SECUBOX_AD_ALLOWLIST", str(allow))
    monkeypatch.setenv("SECUBOX_SOCIAL_MIN_SITES", "3")
    monkeypatch.setenv("SECUBOX_SOCIAL_WINDOW_HOURS", "168")

    al = _load_autolearn()
    n = al._social_feed()

    lines = out.read_text().split()
    assert "tracker.io" in lines                # 3 distinct sites, recent → promoted
    assert "twosite.net" not in lines           # below threshold
    assert "safe.cdn.net" not in lines          # allowlisted
    assert "secubox.in" not in lines            # self domain
    assert "stale.io" not in lines              # outside window
    assert "preexisting.tracker.com" in lines   # merge, not overwrite
    assert len(lines) == len(set(lines))        # no dups
    assert n == 1


def test_social_feed_no_table_is_safe(tmp_path, monkeypatch):
    db = tmp_path / "empty.db"
    sqlite3.connect(db).close()  # no social_edges table
    out = tmp_path / "learned-trackers.txt"
    out.write_text("x.tracker.com\n")
    monkeypatch.setenv("SECUBOX_AUTOLEARN_DB", str(db))
    monkeypatch.setenv("SECUBOX_AUTOLEARN_OUT", str(out))
    al = _load_autolearn()
    n = al._social_feed()
    assert n == -1                              # gated/unavailable, not a crash
    assert "x.tracker.com" in out.read_text()   # file untouched
