# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import os, sqlite3, subprocess, sys, pathlib, json

PKG = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = PKG / "sbin" / "secubox-toolbox-autolearn"


def _seed_db(path):
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE threat_intel (ioc TEXT, type TEXT);
        CREATE TABLE social_edges (ts INTEGER, client_mac_hash TEXT,
            src_site TEXT, tracker_domain TEXT, cookie_id_hash TEXT,
            ja4_hash TEXT, consent_state TEXT DEFAULT 'none_seen');
        CREATE TABLE social_nodes (client_mac_hash TEXT, tracker_domain TEXT,
            hits INTEGER, sites_jsonl TEXT, pre_consent_hits INTEGER DEFAULT 0);
        CREATE TABLE social_host_meta (tracker_domain TEXT PRIMARY KEY,
            cdn_vendor TEXT, opgrade_vendor TEXT, antibot_vendor TEXT);
    """)
    for site in ("a.example", "b.example2"):
        c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,"
                  "tracker_domain,cookie_id_hash,ja4_hash,consent_state) "
                  "VALUES(1,'m','%s','www.criteo.com','CID','j','pre_consent')" % site)
    c.execute("INSERT INTO threat_intel VALUES('evil.trk','domain')")
    c.execute("INSERT INTO social_nodes(client_mac_hash,tracker_domain,hits,"
              "sites_jsonl,pre_consent_hits) VALUES('m','evil.trk',1,?,1)",
              (json.dumps(["a.com", "b.com", "c.com"]),))
    c.execute("INSERT INTO social_host_meta(tracker_domain,cdn_vendor) "
              "VALUES('evil.trk',NULL)")
    c.commit(); c.close()


def test_autolearn_writes_both_lists(tmp_path):
    db = tmp_path / "toolbox.db"
    learned = tmp_path / "learned-trackers.txt"
    pure = tmp_path / "pure-trackers.txt"
    _seed_db(str(db))
    env = {**os.environ,
           "SECUBOX_AUTOLEARN_DB": str(db),
           "SECUBOX_AUTOLEARN_OUT": str(learned),
           "SECUBOX_AUTOLEARN_PURE_OUT": str(pure),
           "PYTHONPATH": str(PKG)}
    r = subprocess.run([sys.executable, str(SCRIPT)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    learned_txt = learned.read_text()
    assert "criteo.com" in learned_txt
    assert "evil.trk" in learned_txt
    pure_txt = pure.read_text()
    assert "google-analytics.com" in pure_txt
    assert "evil.trk" in pure_txt
