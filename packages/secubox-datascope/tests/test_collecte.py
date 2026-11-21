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
    assert g["tronque"] is False and len(g["noeuds"]) == sum(ov["entites"].values())
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


def test_deux_passes_sans_changement_aucune_ecriture(cfg):
    collecte.passe(cfg, NOW)
    cache = {n: (cfg.cache / n).stat().st_mtime_ns for n in ("overview.json", "graph.json")}
    db = cfg.base.read_bytes()
    time.sleep(0.01)
    collecte.passe(cfg, NOW + 60)
    assert {n: (cfg.cache / n).stat().st_mtime_ns for n in cache} == cache
    assert cfg.base.read_bytes() == db


def test_graph_borne(cfg, monkeypatch):
    _nac(cfg.nac_db.with_name("gros.db"), 700)
    cfg.nac_db = cfg.nac_db.with_name("gros.db")
    collecte.passe(cfg, NOW)
    g = _lire(cfg, "graph.json")
    assert len(g["noeuds"]) == 500 and g["tronque"] is True
    assert len(g["aretes"]) <= 1500
    ids = {n["id"] for n in g["noeuds"]}
    assert all(a["src"] in ids and a["dst"] in ids for a in g["aretes"])


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
