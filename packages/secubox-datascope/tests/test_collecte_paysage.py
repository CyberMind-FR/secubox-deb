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
from secubox_datascope.connecteurs import paysage  # noqa: E402
from secubox_datascope.store import etat_sources, ouvrir  # noqa: E402

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


def _source(cfg):
    db = ouvrir(Path(cfg.base))
    try:
        return next((s for s in etat_sources(db) if s["source"] == "paysage"), None)
    finally:
        db.close()


def _apercu(cfg):
    d = json.loads((Path(cfg.cache) / "overview.json").read_text())
    return next((s for s in d["sources"] if s["source"] == "paysage"), None)


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
    assert _source(cfg)["motif"] == s["motif"] and "2026" in s["motif"]  # date du relevé : motif stable d'une passe à l'autre
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


def test_passe_eclaircissement_en_echec_ne_defait_pas_l_ecriture(cfg, monkeypatch):
    def boum(db, m):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(paysage_store, "eclaircir", boum)
    _releve(cfg, NOW - 600)
    s = collecte.passe(cfg, NOW)["sources"]["paysage"]
    assert s["etat"] == "ok" and s["ecrit"] is True and "OperationalError" in s["motif"]
    assert len(_instantanes(cfg)) == 1


@pytest.mark.parametrize("blob", [b"pas du zlib", b"", "78da"])
def test_passe_dernier_instantane_illisible_ne_bloque_pas_les_suivants(cfg, blob):
    """R6 : un dernier instantané corrompu compte comme « pas de précédent », la collecte continue et le dit."""
    _releve(cfg, NOW - 3600)
    assert collecte.passe(cfg, NOW - 3500)["sources"]["paysage"]["ecrit"] is True
    db = ouvrir(Path(cfg.base))
    db.execute("UPDATE paysage_instantanes SET graphe = ?", (blob,))
    db.commit()
    db.close()
    r = collecte.passe(cfg, NOW - 3400)  # même relevé : rien à écrire, aucune lecture du graphe corrompu
    assert r["sources"]["paysage"] == {"etat": "inchange", "ecrit": False}
    _releve(cfg, NOW - 1800)
    s = collecte.passe(cfg, NOW - 1700)["sources"]["paysage"]
    assert s["etat"] == "ok" and s["ecrit"] is True and "illisible" in s["motif"]
    db = ouvrir(Path(cfg.base))
    d = paysage_store.dernier(db)
    db.close()
    assert d["epoch"] == NOW - 1800 and d["difference"]["sans_precedent"] == "illisible"
    _releve(cfg, NOW - 100)  # la comparaison reprend, sans motif
    s = collecte.passe(cfg, NOW)["sources"]["paysage"]
    assert s == {"etat": "ok", "ecrit": True}
    db = ouvrir(Path(cfg.base))
    assert "sans_precedent" not in paysage_store.dernier(db)["difference"]
    db.close()


def test_passe_dernier_illisible_et_eclaircissement_en_echec_gardent_les_deux_motifs(cfg, monkeypatch):
    _releve(cfg, NOW - 3600)
    collecte.passe(cfg, NOW - 3500)
    db = ouvrir(Path(cfg.base))
    db.execute("UPDATE paysage_instantanes SET graphe = x'00'")
    db.commit()
    db.close()
    monkeypatch.setattr(paysage_store, "eclaircir", lambda db, m: 1 / 0)
    _releve(cfg, NOW - 600)
    s = collecte.passe(cfg, NOW)["sources"]["paysage"]
    assert s["ecrit"] is True and "illisible" in s["motif"] and "éclaircissement échoué" in s["motif"]


def test_premier_instantane_marque_sans_precedent(cfg):
    _releve(cfg, NOW - 600)
    collecte.passe(cfg, NOW)
    db = ouvrir(Path(cfg.base))
    assert paysage_store.dernier(db)["difference"]["sans_precedent"] == "premier"
    db.close()


def test_etat_du_paysage_publie_comme_les_autres_sources(cfg, monkeypatch):
    """I3 : état et motif dans les curseurs (API /sources) et dans overview.json, pas seulement au journal."""
    r = collecte.passe(cfg, NOW)
    s = _source(cfg)
    assert (s["etat"], s["motif"]) == ("inaccessible", "relevé absent")
    assert r["etat"] == "complet"  # le paysage reste hors de l'état de la passe
    assert (_apercu(cfg)["etat"], _apercu(cfg)["motif"]) == ("inaccessible", "relevé absent")
    vu = s["vu_le"]
    collecte.passe(cfg, NOW + 60)
    assert _source(cfg)["vu_le"] == vu  # rien de nouveau : curseur non réécrit
    vrai = paysage.os.open

    def refus(chemin, *a, **k):
        if str(chemin) == str(cfg.populations):
            raise PermissionError(13, "Permission denied")
        return vrai(chemin, *a, **k)

    with monkeypatch.context() as m:
        m.setattr(paysage.os, "open", refus)
        collecte.passe(cfg, NOW + 120)
    assert _source(cfg)["motif"] == "droit refusé" and _source(cfg)["vu_le"] > vu
    assert _apercu(cfg)["motif"] == "droit refusé"
    _releve(cfg, NOW + 100)
    collecte.passe(cfg, NOW + 180)
    ok = _source(cfg)
    assert (ok["etat"], ok["motif"]) == ("ok", None)
    collecte.passe(cfg, NOW + 240)  # « inchange » est un état sain
    assert _source(cfg) == ok
    _releve(cfg, NOW + 200)
    collecte.passe(cfg, NOW + 300)
    assert _source(cfg)["etat"] == "ok" and _source(cfg)["vu_le"] > ok["vu_le"]


def test_motif_publie_sans_detail_interne(cfg, monkeypatch):
    def boum(*a, **k):
        raise sqlite3.OperationalError("table /chemin/interne verrouillée")

    monkeypatch.setattr(paysage_store, "ecrire", boum)
    _releve(cfg, NOW - 600)
    s = collecte.passe(cfg, NOW)["sources"]["paysage"]
    assert s["motif"] == "erreur interne (OperationalError)" and "/chemin/interne" in s["detail"]  # journal seulement
    assert _source(cfg)["motif"] == "erreur interne (OperationalError)"


def test_publication_de_l_etat_en_echec_ne_fait_pas_echouer_la_passe(cfg, monkeypatch):
    vrai = collecte.appliquer

    def boum(db, releve, quand):
        if releve.source == "paysage":
            raise sqlite3.OperationalError("database is locked")
        return vrai(db, releve, quand)

    monkeypatch.setattr(collecte, "appliquer", boum)
    _releve(cfg, NOW - 600)
    r = collecte.passe(cfg, NOW)
    assert r["etat"] == "complet" and r["sources"]["paysage"]["ecrit"] is True
    assert "OperationalError" in r["sources"]["paysage"]["publication"]


def test_heberge_vient_de_la_topologie_de_la_base(cfg):
    """I2 : seuls les services que la base connaît (relation HOSTED_ON vers cette box) sont « hébergés sur »."""
    _releve(cfg, NOW - 600, [_pop(cibles=["waf", "evil-phish.com", "h", "br-lan"])])
    collecte.passe(cfg, NOW)
    db = ouvrir(Path(cfg.base))
    g = paysage_store.dernier(db)["graphe"]
    db.close()
    heb = [a for a in g["aretes"] if a["type"] == "HEBERGE"]
    assert [a["de"] for a in heb] == ["cible:waf"]
