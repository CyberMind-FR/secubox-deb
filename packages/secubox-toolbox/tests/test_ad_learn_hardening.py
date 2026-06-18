# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#658 — ad-learn must never self-block own infra; promote exact host not registrable."""
import sys
import pathlib
import importlib
import sqlite3
import importlib.util

ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))


def test_allowed_never_blocks_own_infra(monkeypatch, tmp_path):
    # point the allowlist file at a nonexistent path → only the hard-coded
    # _SELF_REGS guard can allow secubox.in
    import ad_ghost
    importlib.reload(ad_ghost)
    monkeypatch.setattr(ad_ghost, "_ALLOW_PATH", str(tmp_path / "nope.txt"))
    assert ad_ghost._allowed("admin.gk2.secubox.in") is True   # own infra
    assert ad_ghost._allowed("kbin.gk2.secubox.in") is True
    assert ad_ghost._allowed("secubox.in") is True
    assert ad_ghost._allowed("ads.doubleclick.net") is False   # real ad host still blockable


def _load_autolearn():
    p = pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-autolearn"
    spec = importlib.util.spec_from_loader("autolearn_h", loader=None)
    mod = importlib.util.module_from_spec(spec)
    exec(compile(p.read_text(), str(p), "exec"), mod.__dict__)
    return mod


def test_ad_feed_exact_host_and_excludes_self(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE ad_candidates(host TEXT, site TEXT, hits INT, last_seen REAL, PRIMARY KEY(host,site));"
        # analytics.tiktok.com seen on 2 sites → promote EXACT, not tiktok.com
        "INSERT INTO ad_candidates VALUES('analytics.tiktok.com','a.com',1,0);"
        "INSERT INTO ad_candidates VALUES('analytics.tiktok.com','b.com',1,0);"
        # our own admin host seen on 2 sites → must NOT promote
        "INSERT INTO ad_candidates VALUES('admin.gk2.secubox.in','a.com',1,0);"
        "INSERT INTO ad_candidates VALUES('admin.gk2.secubox.in','b.com',1,0);")
    con.commit(); con.close()
    out = tmp_path / "learned.txt"
    monkeypatch.setenv("SECUBOX_AUTOLEARN_DB", str(db))
    monkeypatch.setenv("SECUBOX_AUTOLEARN_OUT", str(out))
    monkeypatch.setenv("SECUBOX_AD_ALLOWLIST", str(tmp_path / "allow.txt"))
    monkeypatch.setenv("SECUBOX_AD_MIN_SITES", "2")
    monkeypatch.setenv("SECUBOX_SELF_DOMAINS", "secubox.in")
    al = _load_autolearn()
    al._ad_feed()
    learned = set(out.read_text().split())
    assert "analytics.tiktok.com" in learned          # exact host promoted
    assert "tiktok.com" not in learned                # NOT the parent site
    assert "admin.gk2.secubox.in" not in learned      # own infra excluded
    assert "secubox.in" not in learned
