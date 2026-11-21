# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Montée depuis 0.4.0 (#3725) : état d'une box en 0.4.0 (veille.db migrations 0001 à 0004 avec lignes, memoire.db,
preferences.toml, historique), ouvert comme le service le fait au démarrage. Rien ne se perd, 0005 à 0009 sont
appliquées, la sauvegarde veille.db.avant-0005 existe et reflète l'état d'avant."""
import shutil
import sqlite3

import pytest

from api import memoire
from veille import base


@pytest.fixture
def etat(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path))
    return tmp_path


def _scripts_jusqu_a(tmp_path, maxi):
    dossier = tmp_path / "migrations-040"
    dossier.mkdir()
    for f in sorted(base.MIGRATIONS.glob("[0-9][0-9][0-9][0-9]-*.sql")):
        if int(f.name[:4]) <= maxi:
            shutil.copy(f, dossier / f.name)
    return dossier


def _tables(db):
    return {n for (n,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _etat_040(etat):
    """veille.db telle que 0.4.0 la laisse : migrations 0001 à 0004 et des lignes."""
    db = base.ouvrir(etat / "veille.db", _scripts_jusqu_a(etat, 4))
    assert [v for (v,) in db.execute("SELECT version FROM schema_migrations ORDER BY 1")] == [1, 2, 3, 4]
    for i in range(50):
        db.execute("INSERT INTO evenements(id, source, id_source, noeud, horodatage, famille, gravite, ip_src, "
                   "attributs_json, empreinte, cree_le) VALUES (?, 'menaces', ?, 'gk2', ?, 'scanners', 'low', ?, '{}', ?, "
                   "'2026-11-01T00:00:00Z')", (f"e{i}", f"1:{i}", f"2026-11-01T10:{i:02d}:00Z", f"100.64.9.{i}", f"emp{i}"))
    db.execute("INSERT INTO dossiers(id, cle, type, gravite, premiere_vue, derniere_vue, maj_le) "
               "VALUES ('d1', '100.64.9.1', 'acteur', 'low', '2026-11-01T10:01:00Z', '2026-11-01T10:30:00Z', "
               "'2026-11-01T10:30:00Z')")
    db.close()


def test_montee_depuis_040_sans_perte(etat):
    # Données de 0.4.0 : veille.db, memoire.db (souvenirs et historique), préférences.
    _etat_040(etat)
    memoire.memoire_ajouter("note", "Titre", "Le serveur de gk2 écoute sur le port 8443.", source="test")
    memoire.historique_ajouter("analyse", "Un titre", "Un texte d'historique.", sources=["a"])
    prefs = etat / "preferences.toml"
    prefs.write_text('[moteur]\nmode = "local"\n', encoding="utf-8")
    modele = etat / "modeles"
    modele.mkdir()
    (modele / "petit.gguf").write_bytes(b"GGUF" + bytes(64))
    avant_memoire = (etat / "memoire.db").read_bytes()

    # Le service ouvre la base avec toutes les migrations du paquet 2.0.0.
    db = base.ouvrir(etat / "veille.db")
    try:
        versions = [v for (v,) in db.execute("SELECT version FROM schema_migrations ORDER BY 1")]
        assert versions == [1, 2, 3, 4, 5, 6, 7, 8, 9]
        assert db.execute("SELECT COUNT(*) FROM evenements").fetchone()[0] == 50
        assert db.execute("SELECT cle FROM dossiers").fetchall() == [("100.64.9.1",)]
        assert {"analyses", "actions", "redescentes"} <= _tables(db)
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        db.close()

    # Sauvegarde d'avant la première migration en attente, et elle seule ; elle ne contient rien de 0005 et suiv.
    sauvegardes = sorted(p.name for p in etat.glob("veille.db.avant-*"))
    assert sauvegardes == ["veille.db.avant-0005"]
    sauve = sqlite3.connect(str(etat / "veille.db.avant-0005"))
    try:
        assert sauve.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (4,)
        assert sauve.execute("SELECT COUNT(*) FROM evenements").fetchone() == (50,)
        assert "analyses" not in _tables(sauve)
    finally:
        sauve.close()

    # La montée ne touche ni la mémoire, ni les préférences, ni les modèles.
    c = sqlite3.connect(str(etat / "memoire.db"))
    try:
        assert c.execute("SELECT COUNT(*) FROM souvenirs").fetchone() == (1,)
        assert c.execute("SELECT COUNT(*) FROM historique").fetchone() == (1,)
    finally:
        c.close()
    assert (etat / "memoire.db").exists() and avant_memoire[:16] == b"SQLite format 3\x00"
    assert prefs.read_text(encoding="utf-8") == '[moteur]\nmode = "local"\n'
    assert (modele / "petit.gguf").read_bytes().startswith(b"GGUF")


def test_deuxieme_demarrage_ne_refait_rien(etat):
    _etat_040(etat)
    base.ouvrir(etat / "veille.db").close()
    sauve = etat / "veille.db.avant-0005"
    quand = sauve.stat().st_mtime_ns
    db = base.ouvrir(etat / "veille.db")
    try:
        assert base.migrer(db) == []
        assert [v for (v,) in db.execute("SELECT version FROM schema_migrations ORDER BY 1")] == list(range(1, 10))
    finally:
        db.close()
    assert sauve.stat().st_mtime_ns == quand and [p.name for p in etat.glob("veille.db.avant-*")] == ["veille.db.avant-0005"]
