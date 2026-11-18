# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — sources de secubox-garde : alertes DNS, propositions actord, voisins, DoH."""
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from garde import base, sources  # noqa: E402


def _alerte(ip, i, regle="r", type_="malicious"):
    return json.dumps({"id": i, "type": type_, "severity": "high", "domain": "x.test", "client_ip": ip,
                       "details": {"rule": regle}, "timestamp": "2026-11-18T10:00:00Z", "blocked": False}) + "\n"


def test_alertes_incrementales(tmp_path):
    db = base.ouvrir(tmp_path / "g.db")
    f = tmp_path / "a.jsonl"
    f.write_text(_alerte("192.168.1.5", 1) + _alerte("192.168.1.6", 2))
    s = sources.lire_alertes_dns(db, f, {"192.168.1.5": "aa:bb"})
    assert [x.ip for x in s] == ["192.168.1.5", "192.168.1.6"]
    assert s[0].mac == "aa:bb" and s[1].mac is None and s[0].regle == "r" and s[0].type == "malicious"
    assert s[0].ts == 1794996000  # 2026-11-18T10:00:00Z
    assert sources.lire_alertes_dns(db, f, {}) == []
    with open(f, "a") as fh:
        fh.write(_alerte("192.168.1.7", 3))
    assert [x.ip for x in sources.lire_alertes_dns(db, f, {})] == ["192.168.1.7"]


def test_rotation_alertes(tmp_path):
    db = base.ouvrir(tmp_path / "g.db")
    f = tmp_path / "a.jsonl"
    f.write_text(_alerte("192.168.1.5", 1) + _alerte("192.168.1.6", 2))
    sources.lire_alertes_dns(db, f, {})
    f.rename(tmp_path / "a.old")
    f.write_text(_alerte("192.168.1.9", 9))
    assert [x.ip for x in sources.lire_alertes_dns(db, f, {})] == ["192.168.1.9"]


def test_ligne_invalide_ignoree(tmp_path):
    db = base.ouvrir(tmp_path / "g.db")
    f = tmp_path / "a.jsonl"
    f.write_text("pas du json\n" + _alerte(None, 1) + "[1]\n" + _alerte("192.168.1.5", 2))
    assert [x.ip for x in sources.lire_alertes_dns(db, f, {})] == ["192.168.1.5"]


def test_propositions_vers_signaux(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps({"genere_le": 1000, "propositions": [
        {"raison": "scan", "ips": ["1.2.3.4", "5.6.7.8"]}, {"raison": "autre", "ips": ["1.2.3.4"]}]}))
    s = sources.lire_propositions(f, 5)
    assert [(x.ip, x.type, x.regle, x.ts) for x in s] == [("1.2.3.4", "intrusion", "scan", 1000),
                                                          ("5.6.7.8", "intrusion", "scan", 1000)]
    assert sources.lire_propositions(tmp_path / "absent.json") == []


def test_voisins_json():
    sortie = json.dumps([
        {"dst": "192.168.1.5", "lladdr": "AA:BB:CC:00:00:01", "state": ["REACHABLE"]},
        {"dst": "192.168.1.6", "lladdr": "aa:bb:cc:00:00:02", "state": ["STALE"]},
        {"dst": "192.168.1.7", "state": ["FAILED"]},
        {"dst": "192.168.1.8", "lladdr": "aa:bb:cc:00:00:03", "state": ["FAILED"]}])
    assert sources.voisins(runner=lambda c: sortie) == {
        "192.168.1.5": "aa:bb:cc:00:00:01", "192.168.1.6": "aa:bb:cc:00:00:02"}
    assert sources.voisins(runner=lambda c: "nope") == {}


def test_doh_par_client(tmp_path):
    l = tmp_path / "doh.txt"
    l.write_text("# c\n1.1.1.1\ndns.google  # x\n\ncloudflare-dns.com\n")
    noms = sources.charger_noms_doh(l)
    assert noms == {"dns.google", "cloudflare-dns.com"}
    ev = [{"client_ip": "192.168.1.5", "domaine": "dns.google", "ts": 10},
          {"client_ip": "192.168.1.5", "domaine": "dns.google", "ts": 11},
          {"client_ip": "192.168.1.6", "domaine": "exemple.fr", "ts": 12}]
    s = sources.signaux_doh(ev, noms, {"192.168.1.5": "aa:bb"})
    assert [(x.ip, x.type, x.mac, x.domaine) for x in s] == [("192.168.1.5", "doh", "aa:bb", "dns.google")]


def test_requetes_dns_lecture_seule(tmp_path):
    p = tmp_path / "dnstv.db"
    cx = sqlite3.connect(p)
    cx.execute("CREATE TABLE dnstv_recents (ts INTEGER, client TEXT, domaine TEXT, qtype TEXT, decision TEXT, categorie TEXT)")
    cx.execute("INSERT INTO dnstv_recents VALUES (5,'192.168.1.5','dns.google','A','ALLOWED','')")
    cx.commit()
    cx.close()
    assert sources.lire_requetes_dns(0, p) == [{"client_ip": "192.168.1.5", "domaine": "dns.google", "ts": 5}]
    assert sources.lire_requetes_dns(0, tmp_path / "x.db") == []


def test_troncature_meme_inode(tmp_path):
    db = base.ouvrir(tmp_path / "g.db")
    f = tmp_path / "a.jsonl"
    f.write_text(_alerte("192.168.1.5", 1) + _alerte("192.168.1.6", 2))
    sources.lire_alertes_dns(db, f, {})
    f.write_text(_alerte("192.168.1.9", 9))          # même inode, plus petit
    assert [x.ip for x in sources.lire_alertes_dns(db, f, {})] == ["192.168.1.9"]


def test_derniere_ligne_incomplete(tmp_path):
    db = base.ouvrir(tmp_path / "g.db")
    f = tmp_path / "a.jsonl"
    l2 = _alerte("192.168.1.6", 2)
    f.write_text(_alerte("192.168.1.5", 1) + l2.rstrip("\n"))
    assert [x.ip for x in sources.lire_alertes_dns(db, f, {})] == ["192.168.1.5"]
    with open(f, "a") as fh:
        fh.write("\n")
    assert [x.ip for x in sources.lire_alertes_dns(db, f, {})] == ["192.168.1.6"]
    assert sources.lire_alertes_dns(db, f, {}) == []


def _base_dns(p):
    cx = sqlite3.connect(p)
    cx.execute("PRAGMA journal_mode=WAL")
    cx.execute("CREATE TABLE dnstv_recents (ts INTEGER, client TEXT, domaine TEXT, qtype TEXT, decision TEXT, categorie TEXT)")
    cx.executemany("INSERT INTO dnstv_recents VALUES (?,?,?,'A','ALLOWED','')",
                   [(1, "192.168.1.5", "dns.google"), (2, "192.168.1.6", "a.dns.google"),
                    (3, "192.168.1.7", "exemple.fr"), (4, "192.168.1.8", "xdns.google")])
    cx.commit()
    return cx


def test_requetes_dns_shm_en_lecture_seule(tmp_path, monkeypatch, caplog):
    p = tmp_path / "dnstv.db"
    _base_dns(p).close()      # fermeture : WAL replié dans la base (immutable ignore le -wal)
    vrai = sqlite3.connect
    appels = []

    def faux(cible, *a, **k):
        appels.append(cible)
        if "immutable" not in cible:
            raise sqlite3.OperationalError("unable to open database file")
        return vrai(cible, *a, **k)
    monkeypatch.setattr(sources.sqlite3, "connect", faux)
    with caplog.at_level("WARNING"):
        r = sources.lire_requetes_dns(0, p, noms_doh={"dns.google"})
    assert [x["client_ip"] for x in r] == ["192.168.1.5", "192.168.1.6"]
    assert len(appels) == 2 and "immutable=1" in appels[1]
    assert sum("immutable" in m for m in caplog.messages) == 1


def test_requetes_dns_deux_echecs(tmp_path, monkeypatch, caplog):
    p = tmp_path / "dnstv.db"
    _base_dns(p).close()

    def faux(*a, **k):
        raise sqlite3.DatabaseError("boom")
    monkeypatch.setattr(sources.sqlite3, "connect", faux)
    with caplog.at_level("WARNING"):
        assert sources.lire_requetes_dns(0, p) == []
    assert any("illisible" in m for m in caplog.messages)
