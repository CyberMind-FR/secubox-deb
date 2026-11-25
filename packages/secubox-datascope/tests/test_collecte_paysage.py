# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3921 tâche 3 — le collecteur écrit un instantané du paysage à chaque nouveau relevé."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_datascope import collecte, paysage_store  # noqa: E402
from secubox_datascope.config import Config  # noqa: E402
from secubox_datascope.store import ouvrir  # noqa: E402

NOW = 1795000000.0


def _pop(ident="famille:collecte", **kw):
    p = {"id": ident, "famille": "collecte", "nom_cible": "gitea.gk2.secubox.in", "cibles": ["gitea.gk2.secubox.in"],
         "adresses": 120, "reseaux": 2, "bans": 5, "rotation": False,
         "reseaux_top": [{"asn": 3215, "org": "Orange", "classe": "acces", "adresses": 40}]}
    p.update(kw)
    return p


def _releve(cfg, genere_le, pops=None, **kw):
    d = {"genere_le": genere_le, "complet": True, "populations": [_pop()] if pops is None else pops}
    d.update(kw)
    Path(cfg.populations).write_text(json.dumps(d))


@pytest.fixture
def cfg(tmp_path):
    db = sqlite3.connect(tmp_path / "nac.db")
    db.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, interface TEXT, "
               "device_type TEXT, zone TEXT, first_seen INT, last_seen INT, mac_random INT, oui_vendor TEXT)")
    db.execute("INSERT INTO devices VALUES ('aa:bb:cc:00:00:01','10.0.0.1','h','br-lan','pc','lan',1,2,0,'Acme')")
    db.commit()
    db.close()
    (tmp_path / "netstats.json").write_text(json.dumps({"interfaces": {"eth0": {}}}))
    (tmp_path / "modules.json").write_text(json.dumps(
        {"timestamp": NOW, "modules": {"waf": {"overall": "ok", "critical": False, "timestamp": NOW}}}))
    return Config(base=tmp_path / "d" / "ds.db", cache=tmp_path / "cache", nac_db=tmp_path / "nac.db",
                  netstats=tmp_path / "netstats.json", modules=tmp_path / "modules.json",
                  populations=tmp_path / "populations.json")


def _instantanes(cfg):
    db = ouvrir(Path(cfg.base))
    try:
        return [dict(r) for r in db.execute("SELECT ts, epoch FROM paysage_instantanes ORDER BY epoch")]
    finally:
        db.close()


def test_passe_ecrit_un_instantane(cfg):
    _releve(cfg, NOW - 600)
    r = collecte.passe(cfg, NOW)
    assert r["sources"]["paysage"]["etat"] == "ok" and r["sources"]["paysage"]["ecrit"] is True
    assert r["etat"] == "complet"  # le paysage ne compte pas dans l'état de la passe
    assert len(_instantanes(cfg)) == 1
    db = ouvrir(Path(cfg.base))
    d = paysage_store.dernier(db)
    db.close()
    assert d["epoch"] == NOW - 600 and d["partiel"] is False
    assert "pop:famille:collecte" in d["difference"]["apparus"]


def test_passe_inchange(cfg):
    _releve(cfg, NOW - 600)
    collecte.passe(cfg, NOW)
    r = collecte.passe(cfg, NOW + 300)
    assert r["sources"]["paysage"]["etat"] == "inchange" and r["sources"]["paysage"]["ecrit"] is False
    assert len(_instantanes(cfg)) == 1


def test_passe_difference_avec_le_precedent_sans_pas_fixe(cfg):
    _releve(cfg, NOW - 7200, [_pop(adresses=100)])
    collecte.passe(cfg, NOW - 7000)
    _releve(cfg, NOW - 5000, [_pop(adresses=130), _pop("famille:neuve")])  # écart de 2200 s : aucun pas supposé
    r = collecte.passe(cfg, NOW)
    assert r["sources"]["paysage"]["ecrit"] is True
    db = ouvrir(Path(cfg.base))
    d = paysage_store.dernier(db)
    db.close()
    assert "pop:famille:neuve" in d["difference"]["apparus"]
    assert d["difference"]["hausses"] == [{"id": "pop:famille:collecte", "metrique": "adresses", "de": 100, "a": 130}]


def test_passe_genere_le_recule(cfg):
    _releve(cfg, NOW - 600)
    collecte.passe(cfg, NOW)
    _releve(cfg, NOW - 1200)
    r = collecte.passe(cfg, NOW + 60)
    assert r["sources"]["paysage"]["etat"] == "inchange" and r["sources"]["paysage"]["ecrit"] is False
    assert len(_instantanes(cfg)) == 1


def test_passe_genere_le_recule_perime(cfg):
    _releve(cfg, NOW - 90000)
    collecte.passe(cfg, NOW - 86000)  # écrit : premier relevé
    _releve(cfg, NOW - 100000)
    r = collecte.passe(cfg, NOW)
    assert r["sources"]["paysage"]["etat"] == "inaccessible" and r["sources"]["paysage"]["motif"]
    assert len(_instantanes(cfg)) == 1


def test_passe_genere_le_dans_le_futur_ne_bloque_pas(cfg):
    _releve(cfg, NOW + 86400)
    r = collecte.passe(cfg, NOW)
    s = r["sources"]["paysage"]
    assert s["etat"] == "inaccessible" and "futur" in s["motif"] and s["ecrit"] is False
    assert _instantanes(cfg) == []
    _releve(cfg, NOW - 100)  # le relevé correct qui suit est bien écrit
    r = collecte.passe(cfg, NOW + 60)
    assert r["sources"]["paysage"]["ecrit"] is True and len(_instantanes(cfg)) == 1
    _releve(cfg, NOW + 500)  # dans la tolérance de 10 min : accepté
    assert collecte.passe(cfg, NOW + 60)["sources"]["paysage"]["ecrit"] is True


def test_passe_sans_releve(cfg):
    r = collecte.passe(cfg, NOW)
    s = r["sources"]["paysage"]
    assert s["etat"] == "inaccessible" and s["ecrit"] is False and s["motif"]
    assert r["etat"] == "complet" and (Path(cfg.cache) / "graph.json").exists()
    assert (Path(cfg.cache) / "overview.json").exists()
    assert _instantanes(cfg) == []


def test_passe_releve_corrompu(cfg):
    Path(cfg.populations).write_text("{pas du json")
    r = collecte.passe(cfg, NOW)
    assert r["sources"]["paysage"]["etat"] == "inaccessible" and (Path(cfg.cache) / "graph.json").exists()


def test_passe_erreur_sqlite_capturee(cfg, monkeypatch):
    _releve(cfg, NOW - 600)

    def boum(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(paysage_store, "ecrire", boum)
    r = collecte.passe(cfg, NOW)
    s = r["sources"]["paysage"]
    assert s["etat"] == "inaccessible" and s["ecrit"] is False and "OperationalError" in s["motif"]
    assert r["etat"] == "complet" and (Path(cfg.cache) / "graph.json").exists()


def test_passe_erreur_inattendue_capturee(cfg, monkeypatch):
    _releve(cfg, NOW - 600)
    monkeypatch.setattr(collecte, "difference", lambda *a, **k: 1 / 0)
    r = collecte.passe(cfg, NOW)
    assert r["sources"]["paysage"]["etat"] == "inaccessible"
    assert (Path(cfg.cache) / "graph.json").exists()


def test_passe_eclaircit_a_chaque_ecriture(cfg, monkeypatch):
    appels = []
    monkeypatch.setattr(paysage_store, "eclaircir", lambda db, m: appels.append(m) or 0)
    _releve(cfg, NOW - 600)
    collecte.passe(cfg, NOW)
    collecte.passe(cfg, NOW + 1)  # inchangé : pas d'éclaircissement
    assert appels == [NOW]
