# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""veille.db (V2 § 6) : ouverture (WAL, clés étrangères, délai de verrou), migrations versionnées avec sauvegarde.

Migrations : `NNNN-nom.sql` appliquées dans l'ordre, chacune dans UNE transaction avec l'inscription de sa version
(un échec l'annule en entier). Avant la première migration en attente d'une base déjà peuplée, la base est copiée
par l'API de sauvegarde SQLite en `veille.db.avant-NNNN` (une seule sauvegarde gardée). La base n'est jamais supprimée.
"""
import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("secubox-ai-veille")

# Installé : /usr/lib/secubox/ai/{veille,migrations} ; en source : packages/secubox-ai/{veille,migrations}.
MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"
_NOM = re.compile(r"^(\d{4})-[\w.-]+\.sql$")


def _horodatage():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connecter(chemin):
    # isolation_level=None : transactions explicites (BEGIN/COMMIT). check_same_thread=False : le service passe par
    # asyncio.to_thread (fils différents) ; ses écritures sont sérialisées par Veille.sql.
    db = sqlite3.connect(str(chemin), timeout=5, isolation_level=None, check_same_thread=False)
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    db.execute("PRAGMA synchronous = NORMAL")
    db.execute("PRAGMA temp_store = FILE")        # SQLITE_TMPDIR = /var/lib/secubox/ai/tmp (unité)
    return db


def _scripts(dossier):
    trouves = []
    for f in sorted(Path(dossier).iterdir()):
        m = _NOM.match(f.name)
        if m:
            trouves.append((int(m.group(1)), f))
    return trouves


def _sauvegarder(db, chemin, version):
    for ancienne in chemin.parent.glob(chemin.name + ".avant-*"):
        ancienne.unlink()
    cible = chemin.with_name(f"{chemin.name}.avant-{version:04d}")
    copie = sqlite3.connect(str(cible))
    try:
        db.backup(copie)
    finally:
        copie.close()


def migrer(db, dossier=MIGRATIONS):
    """Applique les migrations manquantes ; rend les versions appliquées."""
    db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, appliquee_le TEXT NOT NULL)")
    faites = {v for (v,) in db.execute("SELECT version FROM schema_migrations")}
    attente = [(v, f) for v, f in _scripts(dossier) if v not in faites]
    chemin = db.execute("PRAGMA database_list").fetchone()[2]
    appliquees = []
    peuplee = bool(faites)        # sauvegarde avant la première migration en attente d'une base DÉJÀ peuplée
    for version, fichier in attente:
        if peuplee and chemin and not appliquees:
            _sauvegarder(db, Path(chemin), version)
        script = fichier.read_text(encoding="utf-8")
        try:
            db.execute("BEGIN IMMEDIATE")
            for instruction in _instructions(script):
                db.execute(instruction)
            db.execute("INSERT INTO schema_migrations(version, appliquee_le) VALUES (?, ?)", (version, _horodatage()))
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            log.exception("migration %04d refusée, annulée", version)
            raise
        faites.add(version)
        appliquees.append(version)
        log.info("migration %04d appliquée", version)
    return appliquees


def _instructions(script):
    """Découpe un script en instructions complètes (sqlite3.complete_statement ; pas de déclencheurs ici)."""
    courante = ""
    for ligne in script.splitlines(keepends=True):
        courante += ligne
        if sqlite3.complete_statement(courante):
            if courante.strip():
                yield courante
            courante = ""
    if courante.strip() and not all(x.strip().startswith("--") or not x.strip() for x in courante.splitlines()):
        yield courante


def ouvrir(chemin, dossier=MIGRATIONS):
    """Ouvre (et crée) veille.db, applique les migrations manquantes."""
    chemin = Path(chemin)
    db = _connecter(chemin)
    try:
        migrer(db, dossier)
    except sqlite3.Error:
        db.close()
        raise
    return db
