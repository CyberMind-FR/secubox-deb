# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
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


def _nodes_db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE social_nodes (
            client_mac_hash TEXT, tracker_domain TEXT, hits INTEGER,
            sites_jsonl TEXT, pre_consent_hits INTEGER DEFAULT 0);
        CREATE TABLE social_host_meta (
            tracker_domain TEXT PRIMARY KEY, cdn_vendor TEXT,
            opgrade_vendor TEXT, antibot_vendor TEXT);
    """)
    return c


def _node(c, tracker, sites):
    c.execute("INSERT INTO social_nodes(client_mac_hash,tracker_domain,hits,"
              "sites_jsonl,pre_consent_hits) VALUES('m',?,1,?,1)",
              (tracker, json.dumps(sites)))


def _meta(c, tracker, cdn=None):
    c.execute("INSERT INTO social_host_meta(tracker_domain,cdn_vendor) "
              "VALUES(?,?)", (tracker, cdn))


def test_pure_seed_always_present():
    c = _nodes_db()
    pure = learn.pure_trackers(c, learned=set(), seed=learn.PURE_SEED)
    assert "google-analytics.com" in pure
    assert "doubleclick.net" in pure


def test_pure_autopromote_non_cdn_3sites():
    c = _nodes_db()
    _node(c, "evil.trk", ["a.com", "b.com", "c.com"])
    _meta(c, "evil.trk", cdn=None)
    pure = learn.pure_trackers(c, learned={"evil.trk"}, seed=set())
    assert "evil.trk" in pure


def test_pure_not_promoted_when_cdn():
    c = _nodes_db()
    _node(c, "cdn.trk", ["a.com", "b.com", "c.com"])
    _meta(c, "cdn.trk", cdn="cloudflare")
    pure = learn.pure_trackers(c, learned={"cdn.trk"}, seed=set())
    assert "cdn.trk" not in pure


def test_pure_not_promoted_under_3_sites():
    c = _nodes_db()
    _node(c, "small.trk", ["a.com", "b.com"])
    _meta(c, "small.trk", cdn=None)
    pure = learn.pure_trackers(c, learned={"small.trk"}, seed=set())
    assert "small.trk" not in pure


def test_pure_not_promoted_when_first_party():
    c = _nodes_db()
    _node(c, "shop.com", ["shop.com", "b.com", "c.com"])
    _meta(c, "shop.com", cdn=None)
    pure = learn.pure_trackers(c, learned={"shop.com"}, seed=set())
    assert "shop.com" not in pure
