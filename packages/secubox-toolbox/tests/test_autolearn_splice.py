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


def test_splice_feed_never_splices_ad_networks(tmp_path, monkeypatch):
    """Ad/tracker networks must NEVER be promoted to splice.

    Splicing = passthrough, and the #662 ad-candidate feed only fires on the
    allow/mitm path ("never the block 204 / splice paths"). So a spliced ad
    network can never be observed, and the ad auto-learn loop silently starves.
    Ad endpoints serve no HTML and are high-traffic, so they otherwise match the
    splice heuristic perfectly — this is exactly how the 2026-07-23 #ads
    regression happened (regies in splice-learned.txt → 0 candidates learned).
    """
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE splice_host_obs(host TEXT PRIMARY KEY, hits INT, html_hits INT, last_seen REAL);"
        # Real ad/tracker networks: never-HTML + high hits → match the heuristic.
        "INSERT INTO splice_host_obs VALUES('rubiconproject.com',50,0,0);"
        "INSERT INTO splice_host_obs VALUES('pixel.adform.net',40,0,0);"
        "INSERT INTO splice_host_obs VALUES('google-analytics.com',99,0,0);"
        # A legitimate never-HTML asset host must still be spliced.
        "INSERT INTO splice_host_obs VALUES('cdn.assets.net',25,0,0);")
    con.commit(); con.close()
    out = tmp_path / "splice-learned.txt"
    monkeypatch.setenv("SECUBOX_AUTOLEARN_DB", str(db))
    monkeypatch.setenv("SECUBOX_SPLICE_LEARNED_OUT", str(out))
    al = _load_autolearn()
    al._splice_feed()
    learned = set(out.read_text().split())

    assert "rubiconproject.com" not in learned
    assert "pixel.adform.net" not in learned        # matched via its registrable
    assert "google-analytics.com" not in learned
    assert "cdn.assets.net" in learned              # legit passthrough preserved


def test_never_splice_is_env_extensible(tmp_path, monkeypatch):
    """Operators can extend the guard without a code change (mirrors NEVER_LEARN)."""
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE splice_host_obs(host TEXT PRIMARY KEY, hits INT, html_hits INT, last_seen REAL);"
        "INSERT INTO splice_host_obs VALUES('newtracker.example',30,0,0);")
    con.commit(); con.close()
    out = tmp_path / "splice-learned.txt"
    monkeypatch.setenv("SECUBOX_AUTOLEARN_DB", str(db))
    monkeypatch.setenv("SECUBOX_SPLICE_LEARNED_OUT", str(out))
    monkeypatch.setenv("SECUBOX_NEVER_SPLICE", "newtracker.example")
    al = _load_autolearn()
    al._splice_feed()
    assert "newtracker.example" not in set(out.read_text().split())
