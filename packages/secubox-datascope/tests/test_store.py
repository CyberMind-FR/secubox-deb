# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — index SQLite : idempotence, plafonds, provenance, purge, voisins."""
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from secubox_datascope import store  # noqa: E402

T0 = "2026-11-21T10:00:00Z"


@pytest.fixture
def db(tmp_path):
    d = store.ouvrir(tmp_path / "d.db")
    yield d
    d.close()


def ent(i):
    return {"id": f"device:aa{i:04d}", "label": f"d{i}", "attributes": {"n": i}}


def rel(a, b, **kw):
    r = {"src": a, "dst": b, "type": "CONNECTS_TO", "evidence_type": "observed", "confidence": 0.9,
         "justification": "vu dans la table NAC"}
    r.update(kw)
    return r


def releve(n=2, emp="e1", **kw):
    es = [ent(i) for i in range(n)]
    rs = [rel(es[0]["id"], es[1]["id"])] if n > 1 else []
    return store.Releve(source="nac", etat="ok", motif=None, entites=es, relations=rs, empreinte=emp, **kw)


def test_ouvrir_idempotent_et_pragmas(tmp_path):
    for _ in range(2):
        d = store.ouvrir(tmp_path / "x.db")
        assert d.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert d.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert d.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 1
        d.close()


def test_idempotence(db):
    r = store.appliquer(db, releve(), T0)
    assert r["ecrites"] == 3
    avant = db.total_changes
    r2 = store.appliquer(db, releve(), "2026-11-21T10:05:00Z")
    assert r2["ecrites"] == 0 and db.total_changes == avant


def test_empreinte_inchangee_rien_lu(db):
    store.appliquer(db, releve(), T0)
    trace = []
    db.set_trace_callback(trace.append)
    store.appliquer(db, releve(), "2026-11-21T10:05:00Z")
    assert not [s for s in trace if s.split()[0].upper() in ("INSERT", "UPDATE", "DELETE", "BEGIN")]


def test_absente_non_supprimee(db):
    store.appliquer(db, releve(3, "e1"), T0)
    store.appliquer(db, releve(2, "e2"), "2026-11-21T11:00:00Z")
    e = store.entite(db, "device:aa0002")
    assert e and e["last_seen"] == T0
    assert store.entite(db, "device:aa0000")["last_seen"] == "2026-11-21T11:00:00Z"


def test_plafond_entites_refus_signale(db, monkeypatch):
    store.appliquer(db, releve(3, "e1"), T0)
    monkeypatch.setattr(store, "ENTITES_MAX", 3)
    r = store.appliquer(db, store.Releve("nac", "ok", "e2", None, [ent(i) for i in range(5)], []), T0)
    assert r["refusees"] == 2 and r["plafond"] is True
    assert db.execute("SELECT count(*) FROM entities").fetchone()[0] == 3


def test_plafond_relations(db, monkeypatch):
    monkeypatch.setattr(store, "RELATIONS_MAX", 1)
    es = [ent(i) for i in range(3)]
    rs = [rel(es[0]["id"], es[1]["id"]), rel(es[0]["id"], es[2]["id"])]
    r = store.appliquer(db, store.Releve("nac", "ok", "e", None, es, rs), T0)
    assert r["refusees"] == 1 and r["plafond"] is True


def test_plafond_taille_base(db, monkeypatch):
    monkeypatch.setattr(store, "BASE_MAX_OCTETS", 1)
    r = store.appliquer(db, releve(), T0)
    assert r["plafond"] is True and r["ecrites"] == 0


def test_relation_sans_justification_refusee(db):
    es = [ent(0), ent(1)]
    for j in ("", "  ", None):
        with pytest.raises(ValueError):
            store.appliquer(db, store.Releve("nac", "ok", "e", None, es, [rel("device:aa0000", "device:aa0001",
                                                                             justification=j)]), T0)
    assert db.execute("SELECT count(*) FROM entities").fetchone()[0] == 0


def test_evidence_inferred_refusee(db):
    with pytest.raises(ValueError):
        store.appliquer(db, store.Releve("nac", "ok", "e", None, [ent(0), ent(1)],
                                         [rel("device:aa0000", "device:aa0001", evidence_type="inferred")]), T0)


def test_identifiant_invalide_refuse(db):
    for mauvais in ("host:x", "device:", "device:a b", "device:é", "device:" + "a" * 129):
        with pytest.raises(ValueError):
            store.appliquer(db, store.Releve("nac", "ok", "e", None, [{"id": mauvais}], []), T0)


def test_purge_30_jours_par_lots(db, monkeypatch):
    monkeypatch.setattr(store, "LOT_PURGE", 10)
    store.appliquer(db, releve(1), "2026-09-01T00:00:00Z")
    db.execute("DELETE FROM observations")
    for i in range(25):
        db.execute("INSERT INTO observations(entity_id, source_module, observed_at) VALUES "
                   "('device:aa0000','nac','2026-10-01T00:00:00Z')")
    db.execute("INSERT INTO observations(entity_id, source_module, observed_at) VALUES "
               "('device:aa0000','nac','2026-11-20T00:00:00Z')")
    assert store.purger(db, T0) == 25
    assert db.execute("SELECT count(*) FROM observations").fetchone()[0] == 1


def test_voisins_bornes(db):
    es = [{"id": "node:c"}] + [ent(i) for i in range(600)]
    rs = [rel("node:c", e["id"]) for e in es[1:]]
    store.appliquer(db, store.Releve("nac", "ok", "e", None, es, rs), T0)
    v = store.voisins(db, "node:c")
    assert len(v["noeuds"]) == 500 and v["tronque"] is True and len(v["aretes"]) <= 1500
    v2 = store.voisins(db, "device:aa0001")
    assert v2["tronque"] is False and len(v2["noeuds"]) == 2


def test_releve_inaccessible_conserve_index(db):
    store.appliquer(db, releve(), T0)
    store.appliquer(db, store.Releve("nac", "inaccessible", "e9", "base absente", [], []), "2026-11-21T11:00:00Z")
    assert db.execute("SELECT count(*) FROM entities").fetchone()[0] == 2
    s = store.etat_sources(db)[0]
    assert s["etat"] == "inaccessible" and s["motif"] == "base absente" and s["vu_le"] == "2026-11-21T11:00:00Z"


def test_lister_pagination_et_filtre(db):
    store.appliquer(db, releve(5), T0)
    lst, total = store.lister_entites(db, "device", None, 1, 2)
    assert total == 5 and len(lst) == 2
    lst, total = store.lister_entites(db, None, "d3", 1, 1000)
    assert total == 1 and lst[0]["attributes"] == {"n": 3}
    assert store.lister_entites(db, "ip", None, 1, 50) == ([], 0)


def test_migrations_installees_par_rules():
    rules = (RACINE / "debian/rules").read_text(encoding="utf-8")
    assert "usr/lib/secubox/datascope/migrations" in rules and (RACINE / "migrations/0001-socle.sql").is_file()


def test_refus_rejoue_apres_hausse_du_plafond(db, monkeypatch):
    monkeypatch.setattr(store, "ENTITES_MAX", 3)
    rv = lambda: store.Releve("nac", "ok", "e5", None, [ent(i) for i in range(5)], [])  # noqa: E731
    assert store.appliquer(db, rv(), T0)["refusees"] == 2
    monkeypatch.setattr(store, "ENTITES_MAX", 5)
    r = store.appliquer(db, rv(), "2026-11-21T10:05:00Z")
    assert r["refusees"] == 0 and r["ecrites"] >= 2
    assert db.execute("SELECT count(*) FROM entities").fetchone()[0] == 5
    avant = db.total_changes  # passe complète : l'empreinte est posée, plus d'écriture
    store.appliquer(db, rv(), "2026-11-21T10:10:00Z")
    assert db.total_changes == avant


def test_taille_utile_apres_purge(db):
    store.appliquer(db, releve(1), "2026-09-01T00:00:00Z")
    for _ in range(3000):
        db.execute("INSERT INTO observations(entity_id, source_module, observed_at, attributes_json) "
                   "VALUES ('device:aa0000','nac','2026-09-01T00:00:00Z', ?)", ("x" * 200,))
    plein = store._taille(db)
    assert store.purger(db, T0) == 3001
    assert store._taille(db) < plein


def test_bornes_voisins_et_page(db):
    store.appliquer(db, releve(2), T0)
    v = store.voisins(db, "device:aa0000", max_noeuds=0, max_aretes=0)
    assert len(v["noeuds"]) == 1 and v["tronque"] is True
    assert store.lister_entites(db, None, None, 10**30, 50)[0] == []
