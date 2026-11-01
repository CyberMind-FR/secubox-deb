# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Relevés bruts du collecteur de la LED de supervision (ref #3361)."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import releves

PROC_NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  500  5 0 0 0 0 0 0  500  5 0 0 0 0 0 0
 eth2: 123456 789 0 0 0 0 0 0 654321 987 0 0 0 0 0 0
"""


def _ecrire(racine, rel, contenu):
    p = racine / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(contenu if isinstance(contenu, str) else json.dumps(contenu))
    return p


@pytest.fixture
def racine(tmp_path):
    r = tmp_path
    _ecrire(r, "proc/net/dev", PROC_NET_DEV)
    _ecrire(r, "proc/sys/net/netfilter/nf_conntrack_count", "217\n")
    _ecrire(r, "var/cache/secubox/metrics-cache.json", {
        "waf": {"active_bans": 1582, "alerts_today": 3, "waf_blocked": 140515},
        "connections": {"https": 7, "http": 0, "total_tcp": 217},
        "timestamp_epoch": 1793509950})
    _ecrire(r, "run/secubox/actord-mesures.json", {
        "genere_le": 1793509950, "shadow": True,
        "mesures": [{"actor": "ACT-0001", "niveau": 0}, {"actor": "ACT-0002", "niveau": 2},
                    {"actor": "ACT-0003", "niveau": 3}, {"actor": "ACT-0004", "niveau": 4},
                    {"actor": "ACT-0005", "niveau": 5}]})
    _ecrire(r, "var/cache/secubox/health-doctor.json", {
        "generated_at": "2026-11-01T00:00:00Z",
        "summary": {"total": 5, "ok": 2, "fail": 3, "transitions": []},
        "checks": {
            "a": {"ok": True, "details": {"systemd_active": True}},
            "b": {"ok": True, "details": {"systemd_active": True}},
            "c": {"ok": False, "details": {"systemd_active": True}},
            "d": {"ok": False, "details": {"systemd_active": False}},
            "e": {"ok": False, "details": {}}}})
    db = r / "var/lib/secubox/ad-guard/ad-guard.db"
    db.parent.mkdir(parents=True)
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE devices(mac_address TEXT PRIMARY KEY, ip_address TEXT, hostname TEXT, device_type TEXT)")
    c.execute("CREATE TABLE detections(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, client_ip TEXT)")
    c.executemany("INSERT INTO devices(mac_address) VALUES (?)", [("aa",), ("bb",), ("cc",)])
    maintenant = datetime.now(timezone.utc)
    hier = maintenant - timedelta(days=1)
    c.executemany("INSERT INTO detections(timestamp, client_ip) VALUES (?, ?)",
                  [(hier.isoformat(), "1.1.1.1"), (maintenant.isoformat(), "1.1.1.2"),
                   (maintenant.isoformat(), "1.1.1.3")])
    c.commit()
    c.close()
    return r


def test_valeurs_par_cle(racine):
    v = releves.releves(racine)
    attendu = {
        "reseau.octets_in": 123456, "reseau.octets_out": 654321, "reseau.connexions": 217,
        "fw.paquets_in": 789, "fw.paquets_out": 987,
        "waf.requetes": 7, "waf.blocages": 140515, "waf.attaques": 3,
        "actor.evenements": 5, "actor.suspects": 4, "actor.critiques": 2,
        "adguard.requetes": 3, "adguard.trackers": 2, "adguard.appareils": 3,
        "services.actifs": 2, "services.degrades": 1, "services.arretes": 1}
    assert v == attendu
    assert all(isinstance(x, float) for x in v.values())
    assert "fw.bloques" not in v


def test_interface_wan_parametrable(racine):
    assert releves.releves(racine, wan="lo")["reseau.octets_in"] == 500


def test_source_absente_cle_absente(tmp_path):
    assert releves.releves(tmp_path) == {}


def test_source_absente_isolee(racine):
    (racine / "var/cache/secubox/metrics-cache.json").unlink()
    v = releves.releves(racine)
    assert not any(k.startswith("waf.") for k in v)
    assert v["actor.evenements"] == 5


def test_interface_inconnue(racine):
    v = releves.releves(racine, wan="eth9")
    assert "reseau.octets_in" not in v and "fw.paquets_in" not in v
    assert v["reseau.connexions"] == 217


@pytest.mark.parametrize("rel", ["var/cache/secubox/metrics-cache.json",
                                 "run/secubox/actord-mesures.json",
                                 "var/cache/secubox/health-doctor.json"])
def test_json_casse_cle_absente(racine, rel):
    (racine / rel).write_text("{pas du json")
    v = releves.releves(racine)
    assert isinstance(v, dict)
    prefixe = {"var/cache/secubox/metrics-cache.json": "waf.",
               "run/secubox/actord-mesures.json": "actor.",
               "var/cache/secubox/health-doctor.json": "services."}[rel]
    assert not any(k.startswith(prefixe) for k in v)


def test_json_mal_forme_type(racine):
    _ecrire(racine, "run/secubox/actord-mesures.json", {"mesures": "x"})
    _ecrire(racine, "var/cache/secubox/metrics-cache.json", [1, 2])
    v = releves.releves(racine)
    assert not any(k.startswith(("actor.", "waf.")) for k in v)


def test_json_trop_gros_ignore(racine):
    p = racine / "run/secubox/actord-mesures.json"
    p.write_text('{"mesures": [' + " " * (5 * 1024 * 1024) + "]}")
    assert "actor.evenements" not in releves.releves(racine)


def test_base_adguard_illisible(racine):
    (racine / "var/lib/secubox/ad-guard/ad-guard.db").write_bytes(b"pas sqlite" * 100)
    v = releves.releves(racine)
    assert not any(k.startswith("adguard.") for k in v)
    assert v["reseau.connexions"] == 217


def test_proc_illisible(racine):
    (racine / "proc/net/dev").write_text("n'importe quoi")
    (racine / "proc/sys/net/netfilter/nf_conntrack_count").write_text("abc")
    v = releves.releves(racine)
    assert "reseau.octets_in" not in v and "reseau.connexions" not in v


def test_base_adguard_non_modifiee(racine):
    db = racine / "var/lib/secubox/ad-guard/ad-guard.db"
    avant = db.read_bytes()
    releves.releves(racine)
    assert db.read_bytes() == avant


def test_compteurs_nft_somme_sbx_drop():
    sortie = json.dumps({"nftables": [
        {"metainfo": {"version": "1.0"}},
        {"counter": {"family": "inet", "name": "sbx_drop_input_policy", "table": "filter",
                     "packets": 7716, "bytes": 2353431}},
        {"counter": {"family": "inet", "name": "sbx_drop_forward", "table": "filter",
                     "packets": 4, "bytes": 1}},
        {"counter": {"family": "inet", "name": "autre", "table": "filter", "packets": 99, "bytes": 1}}]})
    assert releves.compteurs_nft(sortie) == 7720.0


@pytest.mark.parametrize("sortie", ["", "pas du json", "[]", "{}", '{"nftables": 3}',
                                    '{"nftables": [{"counter": {"name": "sbx_drop_x", "packets": "a"}}, 5, null]}'])
def test_compteurs_nft_invalide_zero(sortie):
    assert releves.compteurs_nft(sortie) == 0.0


def test_compteurs_nft_non_texte():
    assert releves.compteurs_nft(None) == 0.0
