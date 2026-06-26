# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for social.cookie_xsite_detail / _xsite_detail_from_conn (ref #749)."""
import sqlite3
from secubox_toolbox import social


def _edges_db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE social_edges (
            ts INTEGER, client_mac_hash TEXT, src_site TEXT,
            tracker_domain TEXT, cookie_id_hash TEXT, ja4_hash TEXT,
            consent_state TEXT DEFAULT 'none_seen');
    """)
    return c


def _add(c, ts, client, site, tracker, cid, consent="pre_consent"):
    c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,"
              "tracker_domain,cookie_id_hash,ja4_hash,consent_state) "
              "VALUES (?,?,?,?,?,'ja4',?)",
              (ts, client, site, tracker, cid, consent))


def test_crosssite_tracker_detected_with_detail():
    c = _edges_db()
    # same cookie id reused across 2 distinct sites -> cross-site
    _add(c, 100, "m1", "news.example", "www.criteo.com", "CID1")
    _add(c, 200, "m2", "shop.example2", "www.criteo.com", "CID1", consent="post_consent")
    c.commit()
    rows = social._xsite_detail_from_conn(c, since=0, top_n=50)
    assert len(rows) == 1
    t = rows[0]
    assert t["tracker_domain"] == "criteo.com"
    assert t["site_count"] == 2
    assert sorted(t["sites"]) == ["news.example", "shop.example2"]
    assert t["client_count"] == 2
    assert t["cookie_count"] == 1
    assert t["pre_consent_hits"] == 1
    assert t["last_seen"] == 200


def test_single_site_cookie_ignored():
    c = _edges_db()
    _add(c, 100, "m1", "news.example", "tracker.foo", "CID2")
    _add(c, 110, "m1", "news.example", "tracker.foo", "CID2")
    c.commit()
    assert social._xsite_detail_from_conn(c, since=0, top_n=50) == []


def test_null_and_empty_src_site_excluded():
    c = _edges_db()
    _add(c, 100, "m1", "null", "t.bar", "CID3")
    _add(c, 110, "m1", "", "t.bar", "CID3")
    _add(c, 120, "m1", "real.site", "t.bar", "CID3")
    c.commit()
    # only one VALID site remains for CID3 -> not cross-site
    assert social._xsite_detail_from_conn(c, since=0, top_n=50) == []


def test_window_filters_old_edges():
    c = _edges_db()
    _add(c, 100, "m1", "a.example", "t.win", "CIDW")
    _add(c, 200, "m1", "b.example2", "t.win", "CIDW")
    c.commit()
    assert social._xsite_detail_from_conn(c, since=150, top_n=50) == []


def test_ip_literal_tracker_dropped():
    c = _edges_db()
    _add(c, 100, "m1", "a.example", "192.0.2.5", "CIDIP")
    _add(c, 200, "m1", "b.example2", "192.0.2.5", "CIDIP")
    c.commit()
    assert social._xsite_detail_from_conn(c, since=0, top_n=50) == []


def test_ranking_and_top_n_cap():
    c = _edges_db()
    # tracker A: 2 clients ; tracker B: 1 client -> A ranks first
    _add(c, 100, "m1", "s1.x", "a.trk", "A1"); _add(c, 110, "m2", "s2.x", "a.trk", "A1")
    _add(c, 120, "m1", "s1.x", "b.trk", "B1"); _add(c, 130, "m1", "s2.x", "b.trk", "B1")
    c.commit()
    rows = social._xsite_detail_from_conn(c, since=0, top_n=1)
    assert len(rows) == 1
    assert rows[0]["tracker_domain"] == "a.trk"  # registrable of a.trk (_registrable_domain returns last two labels)


def test_envelope_shape_via_conn(monkeypatch):
    c = _edges_db()
    _add(c, 100, "m1", "news.example", "www.criteo.com", "CID1")
    _add(c, 200, "m2", "shop.example2", "www.criteo.com", "CID1")
    c.commit()

    class _Ctx:
        def __enter__(self): return c
        def __exit__(self, *a): return False

    # Freeze time to 300 so since = 300 - 24*3600 < 0, letting ts=100/200 through.
    monkeypatch.setattr(social.time, "time", lambda: 300)
    monkeypatch.setattr(social, "_conn", lambda: _Ctx())
    out = social.cookie_xsite_detail(hours=24, top_n=50)
    assert out["window_hours"] == 24
    assert isinstance(out["generated_at"], int)
    assert out["trackers"][0]["tracker_domain"] == "criteo.com"
