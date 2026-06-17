# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import pathlib
from secubox_toolbox import social


def _db(tmp_path, monkeypatch):
    # _conn() auto-creates the schema via executescript(_SCHEMA) on every call,
    # so simply patching DB_PATH and opening a connection is enough.
    monkeypatch.setattr(social, "DB_PATH", pathlib.Path(tmp_path / "toolbox.db"))
    with social._conn():
        pass
    return social


def _count(s):
    with s._conn() as c:
        return c.execute("SELECT COUNT(*) FROM social_edges").fetchone()[0]


def test_record_edge_skips_ip_literals(tmp_path, monkeypatch):
    s = _db(tmp_path, monkeypatch)
    s._record_edge_sync("m", "news.example", "82.67.100.75", "cid", "ja4", "none_seen")
    s._record_edge_sync("m", "news.example", "2001:db8::1", "cid", "ja4", "none_seen")
    assert _count(s) == 0
    s._record_edge_sync("m", "news.example", "www.criteo.com", "cid", "ja4", "pre_consent")
    assert _count(s) == 1


def test_aggregate_total_excludes_ip_literals(tmp_path, monkeypatch):
    s = _db(tmp_path, monkeypatch)
    import time as _t
    now = int(_t.time())
    with s._conn() as c:
        for td in ("www.criteo.com", "doubleclick.net", "82.67.100.75"):
            c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,"
                      "tracker_domain,cookie_id_hash,ja4_hash,consent_state) "
                      "VALUES(?,?,?,?,?,?,?)",
                      (now, "m", "news.example", td, "cid", "ja4", "none_seen"))
    agg = s.aggregate(hours=24)
    assert agg["total_trackers_seen"] == 2
    assert len(agg["by_tracker_domain"]) == 2
    assert agg["total_trackers_seen"] == len(agg["by_tracker_domain"])
