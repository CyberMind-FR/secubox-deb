# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — collecteur : passe, caches à double tampon, gardes disque."""
import json
import os
import shutil
import sqlite3
import sys
import time
from collections import namedtuple
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from secubox_datascope import collecte  # noqa: E402
from secubox_datascope.config import Config  # noqa: E402

NOW = 1795000000.0


def _nac(chemin, n):
    db = sqlite3.connect(chemin)
    db.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, interface TEXT, "
               "device_type TEXT, zone TEXT, first_seen INT, last_seen INT, mac_random INT, oui_vendor TEXT)")
    db.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?,?)",
                   [(f"aa:bb:cc:{i >> 16 & 255:02x}:{i >> 8 & 255:02x}:{i & 255:02x}", f"10.{i >> 8 & 255}.{i & 255}.1",
                     f"h{i}", "br-lan", "pc", "lan", NOW - 100, NOW - 10, 0, "Acme") for i in range(n)])
    db.commit()
    db.close()


@pytest.fixture
def cfg(tmp_path):
    _nac(tmp_path / "nac.db", 5)
    (tmp_path / "netstats.json").write_text(json.dumps({"interfaces": {"eth0": {}}}))
    (tmp_path / "modules.json").write_text(json.dumps(
        {"timestamp": NOW, "modules": {"waf": {"overall": "ok", "critical": False, "timestamp": NOW}}}))
    return Config(base=tmp_path / "d" / "ds.db", cache=tmp_path / "cache", nac_db=tmp_path / "nac.db",
                  netstats=tmp_path / "netstats.json", modules=tmp_path / "modules.json")


def _lire(cfg, nom):
    return json.loads((cfg.cache / nom).read_text())


def test_passe_complete_ecrit_caches(cfg):
    r = collecte.passe(cfg, NOW)
    assert r["etat"] == "complet" and r["duree_s"] >= 0
    ov, g = _lire(cfg, "overview.json"), _lire(cfg, "graph.json")
    assert ov["complet"] is True and ov["genere_le"].endswith("Z")
    assert ov["entites"]["device"] == 5 and ov["relations"] > 0
    assert {s["source"] for s in ov["sources"]} == {"network", "status"}
    # vue par défaut : jamais d'adresse ip (elles sont dans l'inspecteur) ; tout le reste tient sous les plafonds
    assert g["tronque"] is False and len(g["noeuds"]) == sum(v for k, v in ov["entites"].items() if k != "ip")
    assert not [x for x in g["noeuds"] if x["type"] == "ip"] and g["ip_hors_vue"] == ov["entites"]["ip"]
    n = g["noeuds"][0]
    assert {"id", "type", "label", "source_module"} <= set(n)
    a = g["aretes"][0]
    assert {"src", "dst", "type", "evidence_type", "source_module"} <= set(a)
    assert [x["id"] for x in g["noeuds"]] == sorted(x["id"] for x in g["noeuds"])


def test_passe_degradee_n_ecrase_pas_le_complet(cfg):
    collecte.passe(cfg, NOW)
    avant = _lire(cfg, "overview.json")
    gavant = _lire(cfg, "graph.json")
    cfg.nac_db.unlink()
    r = collecte.passe(cfg, NOW + 300)
    assert r["etat"] == "degrade"
    assert _lire(cfg, "overview.json") == avant
    assert _lire(cfg, "graph.json") == gavant


def test_degrade_ecrase_un_complet_trop_vieux(cfg):
    collecte.passe(cfg, NOW)
    cfg.nac_db.unlink()
    collecte.passe(cfg, NOW + 16 * 60)
    ov = _lire(cfg, "overview.json")
    assert ov["complet"] is False
    assert any(s["source"] == "network" and s["etat"] == "inaccessible" for s in ov["sources"])


def test_garde_disque_abstention(cfg, monkeypatch):
    U = namedtuple("U", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda p: U(10**10, 10**10 - 100 * 2**20, 100 * 2**20))
    r = collecte.passe(cfg, NOW)
    assert r["etat"] == "abstenu" and "disque" in r["motif"]
    assert not cfg.base.exists() and not cfg.cache.exists()


def test_base_plafond_200_mo_abstention(cfg, monkeypatch):
    collecte.passe(cfg, NOW)
    avant = (cfg.cache / "overview.json").read_bytes()
    monkeypatch.setattr(collecte, "BASE_MAX_OCTETS", 1024)
    r = collecte.passe(cfg, NOW + 60)
    assert r["etat"] == "abstenu" and "base" in r["motif"]
    assert (cfg.cache / "overview.json").read_bytes() == avant


def test_ecriture_atomique(cfg):
    collecte.passe(cfg, NOW)
    assert not [p for p in cfg.cache.iterdir() if p.name.endswith(".tmp")]
    assert sorted(p.name for p in cfg.cache.iterdir()) == ["graph.json", "overview.json"]


def _changes(cfg):
    db = sqlite3.connect(cfg.base)
    try:
        return db.execute("SELECT count(*) FROM observations").fetchone()[0], cfg.base.stat().st_size
    finally:
        db.close()


def test_deux_passes_sans_changement_aucune_ecriture(cfg):
    collecte.passe(cfg, NOW)
    g = (cfg.cache / "graph.json").stat().st_mtime_ns
    gb = (cfg.cache / "graph.json").read_bytes()
    ov, base = _lire(cfg, "overview.json"), _changes(cfg)
    time.sleep(0.01)
    collecte.passe(cfg, NOW + 60)
    assert (cfg.cache / "graph.json").stat().st_mtime_ns == g and (cfg.cache / "graph.json").read_bytes() == gb
    assert _changes(cfg) == base
    ov2 = _lire(cfg, "overview.json")
    assert ov2["genere_le"] == ov["genere_le"] and ov2["verifie_le"] > ov["verifie_le"]
    assert ov2["verifie_le"].endswith("Z")


def test_verifie_le_n_avance_pas_sur_conserve(cfg):
    collecte.passe(cfg, NOW)
    avant = (cfg.cache / "overview.json").read_bytes()
    cfg.nac_db.unlink()
    assert collecte.passe(cfg, NOW + 60)["etat"] == "degrade"
    assert (cfg.cache / "overview.json").read_bytes() == avant


def test_verifie_le_n_avance_pas_sur_abstention(cfg, monkeypatch):
    collecte.passe(cfg, NOW)
    avant = (cfg.cache / "overview.json").read_bytes()
    monkeypatch.setattr(collecte, "BASE_MAX_OCTETS", 1024)
    assert collecte.passe(cfg, NOW + 60)["etat"] == "abstenu"
    assert (cfg.cache / "overview.json").read_bytes() == avant


def test_erreur_temporaire_sans_echec_d_unite(cfg, monkeypatch, capsys):
    """Seuls un verrou ou une base occupée sont temporaires (exit 0) ; le reste est une vraie erreur (exit 1)."""
    monkeypatch.setattr(collecte, "charger", lambda: cfg)

    def leve(e):
        def f(*a, **k):
            raise e
        return f
    for e in (sqlite3.OperationalError("database is locked"), sqlite3.OperationalError("database is busy"),
              sqlite3.OperationalError("database table is locked")):
        monkeypatch.setattr(collecte, "passe", leve(e))
        assert collecte.main() == 0, e
        assert json.loads(capsys.readouterr().out)["etat"] == "erreur_temporaire"


@pytest.mark.parametrize("e", [PermissionError(13, "refus"), OSError(28, "plein"), OSError(30, "lecture seule"),
                               sqlite3.OperationalError("unable to open database file"),
                               sqlite3.OperationalError("no such table: entities"), ValueError("bug")])
def test_vraie_erreur_unite_en_echec(cfg, monkeypatch, capsys, e):
    monkeypatch.setattr(collecte, "charger", lambda: cfg)

    def f(*a, **k):
        raise e
    monkeypatch.setattr(collecte, "passe", f)
    assert collecte.main() == 1
    ligne = json.loads(capsys.readouterr().out)
    assert ligne["etat"] == "erreur" and ligne["motif"] == type(e).__name__


def _nac_recents(chemin, n, iface="br-lan"):
    """n appareils sur une interface, chacun avec son adresse ip."""
    db = sqlite3.connect(chemin)
    db.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, interface TEXT, "
               "device_type TEXT, zone TEXT, first_seen INT, last_seen INT, mac_random INT, oui_vendor TEXT)")
    db.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?,?)",
                   [(f"aa:bb:cc:{i >> 16 & 255:02x}:{i >> 8 & 255:02x}:{i & 255:02x}", f"10.{i >> 8 & 255}.{i & 255}.1",
                     f"h{i}", iface, "pc", "lan", NOW - 100, NOW - 10, 0, "Acme") for i in range(n)])
    db.commit()
    db.close()


def test_graph_par_defaut_priorise_box_et_interfaces(cfg):
    """gk2 : 772 appareils + 772 ip. La vue par défaut garde la box, ses interfaces, zones et services, et 60
    appareils au plus par interface (les plus récemment vus) ; jamais d'ip ; arêtes entre retenus."""
    _nac_recents(cfg.nac_db.with_name("gros.db"), 800)
    cfg.nac_db = cfg.nac_db.with_name("gros.db")
    collecte.passe(cfg, NOW)
    # 100 appareils revus plus tard : ce sont eux que la vue garde (last_seen DESC)
    db = sqlite3.connect(cfg.base)
    db.execute("UPDATE entities SET last_seen = '2030-01-01T00:00:00Z' WHERE id IN "
               "(SELECT id FROM entities WHERE type = 'device' ORDER BY id DESC LIMIT 100)")
    recents = {r[0] for r in db.execute("SELECT id FROM entities WHERE type = 'device' ORDER BY id DESC LIMIT 100")}
    db.commit()
    db.close()
    g = collecte._vue_graphe(collecte.ouvrir(cfg.base), "2026-11-21T00:00:00Z", True)
    ids = {n["id"] for n in g["noeuds"]}
    hote = [n for n in g["noeuds"] if n["type"] == "node"]
    assert len(hote) == 1
    assert {"interface:br-lan", "interface:eth0", "network:lan", "service:waf"} <= ids
    assert not [i for i in ids if i.startswith("ip:")] and g["ip_hors_vue"] == 800
    devs = {i for i in ids if i.startswith("device:")}
    assert len(devs) == collecte.MAX_PAR_IF == 60 and devs <= recents
    assert g["tronque"] is True
    assert len(g["aretes"]) <= 1500
    assert all(a["src"] in ids and a["dst"] in ids for a in g["aretes"])
    paires = {(a["src"], a["dst"], a["type"]) for a in g["aretes"]}
    noeud = hote[0]["id"]
    assert ("interface:br-lan", noeud, "BELONGS_TO") in paires and ("interface:eth0", noeud, "BELONGS_TO") in paires
    assert ("service:waf", noeud, "HOSTED_ON") in paires
    assert all((d, "interface:br-lan", "CONNECTS_TO") in paires for d in devs)
    # le cache écrit par la passe suit la même règle
    collecte.passe(cfg, NOW + 60)
    gc = _lire(cfg, "graph.json")
    assert noeud in {n["id"] for n in gc["noeuds"]} and "interface:br-lan" in {n["id"] for n in gc["noeuds"]}
    assert gc["aretes"]


def test_graph_soixante_par_interface_et_sans_interface(cfg):
    db = sqlite3.connect(cfg.nac_db)
    db.executemany("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?,?)",
                   [(f"aa:bb:dd:00:{i >> 8 & 255:02x}:{i & 255:02x}", None, f"w{i}", "wlan0" if i % 2 else None,
                     "pc", None, NOW - 100, NOW - 10, 0, None) for i in range(300)])
    db.commit()
    db.close()
    collecte.passe(cfg, NOW)
    g = _lire(cfg, "graph.json")
    ids = {n["id"] for n in g["noeuds"]}
    assert "interface:wlan0" in ids and "interface:br-lan" in ids
    par_if = {}
    for a in g["aretes"]:
        if a["type"] == "CONNECTS_TO":
            par_if.setdefault(a["dst"], set()).add(a["src"])
    assert len(par_if["interface:wlan0"]) == 60 and len(par_if["interface:br-lan"]) == 5
    connectes = set().union(*par_if.values())
    sans = {i for i in ids if i.startswith("device:")} - connectes
    assert len(sans) == 60 and g["tronque"] is True


def test_main_rend_zero_et_une_ligne_json(cfg, monkeypatch, capsys):
    monkeypatch.setattr(collecte, "charger", lambda: cfg)
    assert collecte.main() == 0
    sortie = capsys.readouterr().out.strip().splitlines()
    assert len(sortie) == 1 and json.loads(sortie[0])["etat"] in ("complet", "degrade", "abstenu")


def test_mille_appareils_sous_2_s(cfg):
    _nac(cfg.nac_db.with_name("mille.db"), 1000)
    cfg.nac_db = cfg.nac_db.with_name("mille.db")
    t = time.monotonic()
    r = collecte.passe(cfg, NOW)
    assert r["etat"] == "complet"
    assert time.monotonic() - t < 2.0
    assert os.path.getsize(cfg.base) < 200 * 2**20


def test_collecteur_temp_en_memoire(cfg):
    """AppArmor ne donne aucun /tmp au collecteur : tris et table temporaire de la vue restent en mémoire."""
    db = collecte.ouvrir(cfg.base)
    try:
        assert db.execute("PRAGMA temp_store").fetchone()[0] == 2
    finally:
        db.close()
