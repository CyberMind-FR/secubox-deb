# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sqlite3
from secubox_toolbox import learn


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


def _add(c, client, site, tracker, cid, consent="pre_consent"):
    c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,"
              "tracker_domain,cookie_id_hash,ja4_hash,consent_state) "
              "VALUES (1,?,?,?,?,'ja4',?)",
              (client, site, tracker, cid, consent))


def test_cookie_xsite_crosssite_preconsent_detected():
    c = _edges_db()
    _add(c, "m1", "news.example", "www.criteo.com", "CID1")
    _add(c, "m1", "shop.example2", "www.criteo.com", "CID1")
    c.commit()
    out = learn.cookie_xsite_trackers(c, top_n=5)
    assert "criteo.com" in out


def test_cookie_xsite_single_site_ignored():
    c = _edges_db()
    _add(c, "m1", "news.example", "tracker.foo", "CID2")
    _add(c, "m1", "news.example", "tracker.foo", "CID2")
    c.commit()
    assert learn.cookie_xsite_trackers(c, top_n=5) == []


def test_cookie_xsite_post_consent_only_ignored():
    c = _edges_db()
    _add(c, "m1", "a.example", "t.bar", "CID3", consent="post_consent")
    _add(c, "m1", "b.example2", "t.bar", "CID3", consent="post_consent")
    c.commit()
    assert learn.cookie_xsite_trackers(c, top_n=5) == []


def test_cookie_xsite_top_n_cap_ranks_by_clients():
    c = _edges_db()
    _add(c, "m1", "s1.x", "a.trk", "A1"); _add(c, "m2", "s2.x", "a.trk", "A1")
    _add(c, "m1", "s1.x", "b.trk", "B1"); _add(c, "m1", "s2.x", "b.trk", "B1")
    c.commit()
    out = learn.cookie_xsite_trackers(c, top_n=1)
    assert out == ["a.trk"]
