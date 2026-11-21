# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — connecteurs network (NAC, netstats) et status (santé des modules)."""
import json
import re
import sqlite3
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from secubox_datascope.connecteurs import network, status  # noqa: E402

NOW = 1795000000.0
ID = re.compile(r"^(node|network|interface|device|ip|service):[A-Za-z0-9:._-]{1,128}$")


def _nac(chemin, lignes, wal=True):
    db = sqlite3.connect(chemin)
    if wal:
        db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, interface TEXT, "
               "device_type TEXT, zone TEXT, first_seen INT, last_seen INT, mac_random INT, oui_vendor TEXT)")
    db.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?,?)", lignes)
    db.commit()
    db.close()


def _ligne(mac, ip="192.0.2.10", host="tv-salon.example.net", iface="br-lan", zone=None):
    return (mac, ip, host, iface, "tv", zone, NOW - 100, NOW - 10, 0, "Acme")


@pytest.fixture
def netstats(tmp_path):
    p = tmp_path / "netstats.json"
    p.write_text(json.dumps({"updated": 1, "interfaces": {"eth0": {"rx_bytes": 1}, "wg0": {}}}))
    return p


def test_un_appareil_une_entite(tmp_path, netstats):
    _nac(tmp_path / "n.db", [_ligne(f"aa:bb:cc:dd:ee:{i:02x}", ip=f"192.0.2.{i}") for i in range(5)])
    r = network.lire(tmp_path / "n.db", netstats, "gk2", NOW)
    assert r.etat == "ok"
    assert len([e for e in r.entites if e["id"].startswith("device:")]) == 5
    assert all(ID.match(e["id"]) for e in r.entites)
    assert all(x["evidence_type"] == "observed" and x["confidence"] == 1.0 and x["source_module"] == "nac"
               and "inventaire du NAC, vu le" in x["justification"] for x in r.relations)
    ids = {e["id"] for e in r.entites}
    assert all(x["src"] in ids and x["dst"] in ids for x in r.relations)


def test_ipv6_canonique_et_deux_appareils_deux_ip(tmp_path, netstats):
    _nac(tmp_path / "n.db", [_ligne("aa:bb:cc:dd:ee:01", ip="192.0.2.1"),
                             _ligne("aa:bb:cc:dd:ee:02", ip="2001:0DB8:0000:0000:0000:0000:0000:0001")])
    ids = {e["id"] for e in network.lire(tmp_path / "n.db", netstats, "gk2", NOW).entites}
    assert "ip:2001:db8::1" in ids and "ip:192.0.2.1" in ids


def test_mac_minuscule(tmp_path, netstats):
    _nac(tmp_path / "n.db", [_ligne("AA:BB:CC:DD:EE:FF")])
    ids = {e["id"] for e in network.lire(tmp_path / "n.db", netstats, "gk2", NOW).entites}
    assert "device:aa:bb:cc:dd:ee:ff" in ids


def test_sans_zone_pas_de_reseau_fantome(tmp_path, netstats):
    _nac(tmp_path / "n.db", [_ligne("aa:bb:cc:dd:ee:01", zone=None), _ligne("aa:bb:cc:dd:ee:02", zone="")])
    r = network.lire(tmp_path / "n.db", netstats, "gk2", NOW)
    assert not [e for e in r.entites if e["id"].startswith("network:")]
    assert any(x["type"] == "CONNECTS_TO" and x["dst"] == "interface:br-lan" for x in r.relations)
    assert any(x["type"] == "BELONGS_TO" and x["src"] == "interface:eth0" and x["dst"] == "node:gk2"
               for x in r.relations)


def test_zone_renseignee(tmp_path, netstats):
    _nac(tmp_path / "n.db", [_ligne("aa:bb:cc:dd:ee:01", zone="lan")])
    r = network.lire(tmp_path / "n.db", netstats, "gk2", NOW)
    assert any(x["dst"] == "network:lan" and x["src"] == "device:aa:bb:cc:dd:ee:01" for x in r.relations)


def test_nac_verrouillee_index_conserve(tmp_path, netstats):
    _nac(tmp_path / "n.db", [_ligne("aa:bb:cc:dd:ee:01")], wal=False)
    verrou = sqlite3.connect(tmp_path / "n.db", isolation_level=None)
    verrou.execute("BEGIN EXCLUSIVE")
    try:
        r = network.lire(tmp_path / "n.db", netstats, "gk2", NOW)
    finally:
        verrou.execute("ROLLBACK")
        verrou.close()
    assert r.etat == "inaccessible" and r.motif and r.entites == [] and r.relations == []


def test_nac_absente_inaccessible(tmp_path, netstats):
    r = network.lire(tmp_path / "absente.db", netstats, "gk2", NOW)
    assert r.etat == "inaccessible" and r.entites == []
    assert not (tmp_path / "absente.db").exists()


def test_aucun_domaine_dans_les_cles(tmp_path, netstats):
    _nac(tmp_path / "n.db", [_ligne("aa:bb:cc:dd:ee:01", host="secret.example.org")])
    r = network.lire(tmp_path / "n.db", netstats, "gk2", NOW)
    dev = next(e for e in r.entites if e["id"].startswith("device:"))
    assert dev["attributes"]["hostname"] == "secret.example.org"
    blob = json.dumps([e["id"] for e in r.entites] + [[x["src"], x["dst"], x["justification"]]
                                                    for x in r.relations])
    assert "example" not in blob and "Acme" not in blob


def test_empreinte_stable(tmp_path, netstats):
    lignes = [_ligne(f"aa:bb:cc:dd:ee:{i:02x}", ip=f"192.0.2.{i}") for i in range(6)]
    _nac(tmp_path / "a.db", lignes)
    _nac(tmp_path / "b.db", list(reversed(lignes)))
    a = network.lire(tmp_path / "a.db", netstats, "gk2", NOW)
    b = network.lire(tmp_path / "b.db", netstats, "gk2", NOW)
    assert a.empreinte and a.empreinte == b.empreinte


def _modules(tmp_path, ts, extra=None):
    p = tmp_path / "modules.json"
    d = {"timestamp": ts, "modules": {"actor": {"name": "actor", "timestamp": ts, "critical": True,
                                                  "layers": {}, "overall": "degraded"}}}
    d.update(extra or {})
    p.write_text(json.dumps(d))
    return p


def test_status_frais(tmp_path):
    from datetime import datetime
    ts = datetime.fromtimestamp(NOW - 10).astimezone().isoformat()
    r = status.lire(_modules(tmp_path, ts), "gk2", NOW, 300)
    assert r.etat == "ok"
    s = next(e for e in r.entites if e["id"] == "service:actor")
    assert s["attributes"] == {"overall": "degraded", "critical": True}
    x = r.relations[0]
    assert (x["type"], x["dst"], x["evidence_type"]) == ("HOSTED_ON", "node:gk2", "reported")
    assert x["justification"].startswith("santé des modules du ")


def test_modules_perime_unknown(tmp_path):
    from datetime import datetime
    ts = datetime.fromtimestamp(NOW - 1000).astimezone().isoformat()
    r = status.lire(_modules(tmp_path, ts), "gk2", NOW, 300)
    assert r.etat == "unknown"
    assert all(e["attributes"]["overall"] == "unknown" for e in r.entites if e["id"].startswith("service:"))


@pytest.mark.parametrize("contenu", ["[1,2]", "{\"modules\": 3}", "pas du json", "{\"timestamp\": 1}"])
def test_modules_forme_inattendue_unknown(tmp_path, contenu):
    p = tmp_path / "modules.json"
    p.write_text(contenu)
    r = status.lire(p, "gk2", NOW)
    assert r.etat == "unknown" and not any(e["id"].startswith("service:") for e in r.entites)


def test_modules_absent_unknown(tmp_path):
    assert status.lire(tmp_path / "x.json", "gk2", NOW).etat == "unknown"


def test_apparmor_lit_wal_et_shm_sans_ecriture():
    # « rk » : SQLite pose un verrou de lecture même en mode=ro ; sans « k », AppArmor le refuse et la base du NAC
    # répond « database is locked » (constaté sur gk2 le 21/11, #3853). Jamais d'écriture.
    p = (RACINE / "apparmor" / "secubox-datascope").read_text(encoding="utf-8")
    for f in ("devices.db", "devices.db-wal", "devices.db-shm"):
        assert re.search(rf"^\s*/var/lib/secubox/nac/{f} rk,$", p, re.M), f
    assert not re.search(r"/var/lib/secubox/nac/\S+ (rw|w|a)", p)


@pytest.mark.parametrize("mauvais", [1e30, -5, "hier", None, float("inf")])
def test_last_seen_corrompu_ne_fait_pas_echouer(tmp_path, netstats, mauvais):
    lignes = [_ligne("aa:bb:cc:dd:ee:01", ip="192.0.2.1"), _ligne("aa:bb:cc:dd:ee:02", ip="192.0.2.2")]
    lignes[1] = lignes[1][:7] + (lignes[1][7],) + lignes[1][8:]
    mauvaise = list(_ligne("aa:bb:cc:dd:ee:03", ip="192.0.2.3"))
    mauvaise[7] = mauvais
    _nac(tmp_path / "n.db", lignes + [tuple(mauvaise)])
    r = network.lire(tmp_path / "n.db", netstats, "gk2", NOW)
    assert r.etat == "ok"
    ids = {e["id"] for e in r.entites}
    assert {"device:aa:bb:cc:dd:ee:01", "device:aa:bb:cc:dd:ee:02", "ip:192.0.2.1"} <= ids


def test_ipv4_mappee_et_zone_link_local(tmp_path, netstats):
    _nac(tmp_path / "n.db", [_ligne("aa:bb:cc:dd:ee:01", ip="::ffff:192.0.2.1"),
                             _ligne("aa:bb:cc:dd:ee:02", ip="fe80::1%eth0")])
    ids = {e["id"] for e in network.lire(tmp_path / "n.db", netstats, "gk2", NOW).entites}
    assert "ip:192.0.2.1" in ids and "ip:fe80::1" in ids
    assert not [i for i in ids if "%" in i or "ffff" in i]


def test_status_date_future_perimee(tmp_path):
    from datetime import datetime
    ts = datetime.fromtimestamp(NOW + 120).astimezone().isoformat()
    assert status.lire(_modules(tmp_path, ts), "gk2", NOW, 300).etat == "unknown"
    ts = datetime.fromtimestamp(NOW + 30).astimezone().isoformat()
    assert status.lire(_modules(tmp_path, ts), "gk2", NOW, 300).etat == "ok"


def test_suffixe_fin_de_ligne_ecarte_sans_casser_la_passe(tmp_path):
    """« eth0\\n » passait `^…$` (le $ accepte un \\n final) puis faisait refuser tout le relevé par le store."""
    from secubox_datascope import store
    from secubox_datascope.connecteurs._commun import suffixe_valide
    assert suffixe_valide("eth0") and not suffixe_valide("eth0\n") and not suffixe_valide("eth0\n\n")
    ns = tmp_path / "ns.json"
    ns.write_text(json.dumps({"interfaces": {"eth0\n": {}, "eth1": {}}}))
    _nac(tmp_path / "n.db", [_ligne("aa:bb:cc:dd:ee:01", iface="br-lan\n", zone="lan\n")])
    r = network.lire(tmp_path / "n.db", ns, "gk2", NOW)
    ids = {e["id"] for e in r.entites}
    assert "interface:eth1" in ids and not [i for i in ids if "\n" in i]
    db = store.ouvrir(tmp_path / "ds.db")
    try:
        res = store.appliquer(db, r, "2026-11-21T10:00:00Z")
        assert res["refusees"] == 0
        assert db.execute("SELECT count(*) FROM entities WHERE id = 'interface:eth1'").fetchone()[0] == 1
    finally:
        db.close()


def test_appareil_porte_vu_nac_au_jour_et_ip(tmp_path, netstats):
    """Date du NAC (au jour près, UTC) et adresse canonique dans les attributs de l'appareil ; ip absente : pas de clé."""
    _nac(tmp_path / "n.db", [_ligne("aa:bb:cc:dd:ee:01", ip="2001:0DB8::0001"), _ligne("aa:bb:cc:dd:ee:02", ip=None)])
    r = network.lire(tmp_path / "n.db", netstats, "gk2", NOW)
    d = {e["id"]: e for e in r.entites}
    a1, a2 = d["device:aa:bb:cc:dd:ee:01"]["attributes"], d["device:aa:bb:cc:dd:ee:02"]["attributes"]
    assert a1["vu_nac"] == "2026-11-18" and a1["ip"] == "2001:db8::1"
    assert a2["vu_nac"] == "2026-11-18" and "ip" not in a2


@pytest.mark.parametrize("mauvais", [1e30, -5, "hier", None])
def test_vu_nac_absent_si_last_seen_corrompu(tmp_path, netstats, mauvais):
    m = list(_ligne("aa:bb:cc:dd:ee:03"))
    m[7] = mauvais
    _nac(tmp_path / "n.db", [tuple(m)])
    dev = next(e for e in network.lire(tmp_path / "n.db", netstats, "gk2", NOW).entites if e["id"].startswith("device:"))
    assert "vu_nac" not in dev["attributes"]


def test_empreinte_stable_dans_la_journee(tmp_path, netstats):
    """Le NAC avance last_seen à chaque contact : l'empreinte ne bouge qu'au changement de jour."""
    debut = 1794960000  # 2026-11-18T00:00:00Z
    empreintes = []
    for i, vu in enumerate((debut + 60, debut + 40000, debut + 86399, debut + 86400)):
        lg = list(_ligne("aa:bb:cc:dd:ee:01"))
        lg[7] = vu
        _nac(tmp_path / f"{i}.db", [tuple(lg)])
        empreintes.append(network.lire(tmp_path / f"{i}.db", netstats, "gk2", NOW + 86400).empreinte)
    assert empreintes[0] == empreintes[1] == empreintes[2] != empreintes[3]
