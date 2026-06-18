# tests/test_splice_obs.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from pathlib import Path
from secubox_toolbox import store


def _fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", Path(tmp_path) / "t.db")


def test_record_and_never_html(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    for _ in range(20):
        store.record_splice_obs("cdn.assets.net", is_html=False)
    for _ in range(20):
        store.record_splice_obs("www.site.com", is_html=False)
    store.record_splice_obs("www.site.com", is_html=True)   # served HTML once
    hosts = store.never_html_hosts(min_hits=20)
    assert "cdn.assets.net" in hosts
    assert "www.site.com" not in hosts        # html_hits > 0 → excluded


def test_sampling_cap(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    for _ in range(100):
        store.record_splice_obs("x.net", is_html=False)
    # capped at 50 — never grows unbounded
    import sqlite3
    with store._conn() as c:
        hits = c.execute("SELECT hits FROM splice_host_obs WHERE host='x.net'").fetchone()[0]
    assert hits == 50
