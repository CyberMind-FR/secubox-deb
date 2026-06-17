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
    c.commit(); c.close()


def _run(tmp_path, enforce, dns_feed):
    db = tmp_path / "toolbox.db"; _seed_db(str(db))
    filt = tmp_path / "filters.json"
    filt.write_text(json.dumps({"privacy_enforce": enforce,
                                "privacy_dns_feed": dns_feed}))
    dropin = tmp_path / "97-antitrack.conf"
    env = {**os.environ,
           "SECUBOX_AUTOLEARN_DB": str(db),
           "SECUBOX_AUTOLEARN_OUT": str(tmp_path / "learned.txt"),
           "SECUBOX_AUTOLEARN_PURE_OUT": str(tmp_path / "pure.txt"),
           "SECUBOX_FILTERS_PATH": str(filt),
           "SECUBOX_UNBOUND_BLOCK_CONF": str(dropin),
           "SECUBOX_UNBOUND_RELOAD": "0",
           "PYTHONPATH": str(PKG)}
    r = subprocess.run([sys.executable, str(SCRIPT)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return dropin


def test_dns_dropin_written_when_armed(tmp_path):
    dropin = _run(tmp_path, enforce=True, dns_feed=True)
    assert dropin.exists()
    body = dropin.read_text()
    assert 'local-zone: "google-analytics.com." always_nxdomain' in body


def test_dns_dropin_not_written_when_dark(tmp_path):
    dropin = _run(tmp_path, enforce=False, dns_feed=True)
    assert not dropin.exists()
