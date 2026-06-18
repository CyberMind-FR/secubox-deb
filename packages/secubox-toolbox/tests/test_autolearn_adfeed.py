# tests/test_autolearn_adfeed.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sqlite3, importlib.util, pathlib


def _load_autolearn():
    p = pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-autolearn"
    spec = importlib.util.spec_from_loader("autolearn", loader=None)
    mod = importlib.util.module_from_spec(spec)
    exec(compile(p.read_text(), str(p), "exec"), mod.__dict__)
    return mod


def test_ad_feed_promotes_candidates(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE ad_candidates(host TEXT, site TEXT, hits INT, last_seen REAL,"
        " PRIMARY KEY(host,site));"
        # promoted: seen on 2 distinct sites (>= AD_MIN_SITES=2)
        "INSERT INTO ad_candidates VALUES('ads.tracker.io','cnn.com',5,0);"
        "INSERT INTO ad_candidates VALUES('ads.tracker.io','bbc.com',3,0);"
        # single-site only: must NOT be promoted when AD_MIN_SITES=2
        "INSERT INTO ad_candidates VALUES('single.adnet.com','cnn.com',9,0);"
        # allowlisted: on 2 sites but excluded
        "INSERT INTO ad_candidates VALUES('safe.cdn.net','cnn.com',1,0);"
        "INSERT INTO ad_candidates VALUES('safe.cdn.net','bbc.com',1,0);")
    con.commit(); con.close()

    allow = tmp_path / "ad-allowlist.txt"
    allow.write_text("# trusted\nsafe.cdn.net\n")

    out = tmp_path / "learned-trackers.txt"
    out.write_text("preexisting.tracker.com\nads.tracker.io\n")  # pre-existing entry + a dup

    monkeypatch.setenv("SECUBOX_AUTOLEARN_DB", str(db))
    monkeypatch.setenv("SECUBOX_AUTOLEARN_OUT", str(out))
    monkeypatch.setenv("SECUBOX_AD_ALLOWLIST", str(allow))
    monkeypatch.setenv("SECUBOX_AD_MIN_SITES", "2")

    al = _load_autolearn()
    n = al._ad_feed()

    lines = out.read_text().split()
    assert "ads.tracker.io" in lines           # promoted (folds to registrable)
    assert "safe.cdn.net" not in lines          # allowlisted, excluded
    assert "single.adnet.com" not in lines      # only 1 site, below threshold
    assert "preexisting.tracker.com" in lines   # merge, not overwrite
    assert len(lines) == len(set(lines))        # no dups
    assert n == 1                               # one NEW host promoted
