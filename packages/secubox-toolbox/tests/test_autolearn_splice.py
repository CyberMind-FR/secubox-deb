# tests/test_autolearn_splice.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import os, sqlite3, importlib.util, pathlib


def _load_autolearn():
    p = pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-autolearn"
    spec = importlib.util.spec_from_loader("autolearn", loader=None)
    mod = importlib.util.module_from_spec(spec)
    exec(compile(p.read_text(), str(p), "exec"), mod.__dict__)
    return mod


def test_splice_feed_promotes_never_html(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE splice_host_obs(host TEXT PRIMARY KEY, hits INT, html_hits INT, last_seen REAL);"
        "INSERT INTO splice_host_obs VALUES('cdn.assets.net',25,0,0);"
        "INSERT INTO splice_host_obs VALUES('html.site.com',25,3,0);"
        "INSERT INTO splice_host_obs VALUES('low.hits.net',5,0,0);")
    con.commit(); con.close()
    out = tmp_path / "splice-learned.txt"
    monkeypatch.setenv("SECUBOX_AUTOLEARN_DB", str(db))
    monkeypatch.setenv("SECUBOX_SPLICE_LEARNED_OUT", str(out))
    al = _load_autolearn()
    n = al._splice_feed()
    learned = set(out.read_text().split())
    assert "cdn.assets.net" in learned       # never-HTML, >=20 hits
    assert "html.site.com" not in learned     # served HTML
    assert "low.hits.net" not in learned      # too few hits
    assert n == 1
