# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Base SQLite (WAL) et réglages de secubox-garde (#3794).

Le module répond automatiquement aux intrusions, évasions et infections ; chaque décision est
une ligne de `decisions`. Les autres tables portent l'état du moteur : position de lecture des
journaux, libérations en cours, file des notifications, récidives par adresse, adresses posées par
décision (`adresses`), noms DoH fermés (`decision_noms`), registre des appareils (`appareils`,
`appareil_ips`) et repères du moteur (`etat_moteur`).
"""
from __future__ import annotations

import logging
import sqlite3
import tomllib
from pathlib import Path
from typing import Any, Dict

log = logging.getLogger("secubox-garde")

ETAT = Path("/var/lib/secubox/garde")
BASE = ETAT / "garde.db"
REGLAGES = Path("/etc/secubox/garde.toml")

DEFAUTS: Dict[str, Any] = {
    "automatique": True,
    "courriel": "",
    "sms_utilisateur": "",
    "sms_bans": False,
    "quarantaines_max": 3,
    "rafale_bans": 50,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    menace TEXT NOT NULL CHECK (menace IN ('infection','evasion','intrusion','signale')),
    cible TEXT, mac TEXT, ip TEXT, motif TEXT, signe TEXT,
    debut INTEGER, fin INTEGER,
    etat TEXT NOT NULL CHECK (etat IN ('active','levee','echue','levee_en_cours')),
    leve_par TEXT, notifie TEXT
);
CREATE INDEX IF NOT EXISTS decisions_etat ON decisions(etat, fin);
CREATE TABLE IF NOT EXISTS positions (
    source TEXT PRIMARY KEY, inode INTEGER, offset INTEGER
);
CREATE TABLE IF NOT EXISTS liberations (
    mac TEXT, signe TEXT, jusqua INTEGER,
    PRIMARY KEY (mac, signe)
);
CREATE TABLE IF NOT EXISTS file_notifs (
    id INTEGER PRIMARY KEY, canal TEXT, cle TEXT, texte TEXT,
    cree INTEGER, essais INTEGER, envoye INTEGER
);
CREATE TABLE IF NOT EXISTS recidives (
    ip TEXT PRIMARY KEY, n INTEGER, dernier INTEGER
);
CREATE TABLE IF NOT EXISTS adresses (
    decision_id TEXT NOT NULL, ip TEXT NOT NULL, fin INTEGER, PRIMARY KEY (decision_id, ip)
);
CREATE TABLE IF NOT EXISTS decision_noms (
    decision_id TEXT PRIMARY KEY, noms TEXT
);
CREATE TABLE IF NOT EXISTS appareils (
    cle TEXT PRIMARY KEY, mac TEXT, nom TEXT, vu INTEGER, dernier_signal INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS appareil_ips (
    cle TEXT NOT NULL, ip TEXT NOT NULL, vu INTEGER, PRIMARY KEY (cle, ip)
);
CREATE TABLE IF NOT EXISTS etat_moteur (
    cle TEXT PRIMARY KEY, valeur INTEGER
);
"""


def ouvrir(chemin: Path) -> sqlite3.Connection:
    """Ouvre la base (créée si absente, schéma idempotent), en WAL."""
    cx = sqlite3.connect(str(chemin), timeout=10)
    cx.execute("PRAGMA journal_mode=WAL")
    _migrer(cx)
    cx.executescript(SCHEMA)
    if "fin" not in {r[1] for r in cx.execute("PRAGMA table_info(adresses)")}:
        cx.execute("ALTER TABLE adresses ADD COLUMN fin INTEGER")
    cx.commit()
    return cx


def _migrer(cx: sqlite3.Connection) -> None:
    """0.1/0.2.0 : la contrainte de `decisions.etat` ignore `levee_en_cours` ; table reconstruite, lignes gardées."""
    r = cx.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='decisions'").fetchone()
    if not r or "levee_en_cours" in r[0]:
        return
    cx.executescript("""
BEGIN;
ALTER TABLE decisions RENAME TO decisions_avant;
DROP INDEX IF EXISTS decisions_etat;
""" + SCHEMA.split("CREATE INDEX")[0] + """
INSERT INTO decisions SELECT * FROM decisions_avant;
DROP TABLE decisions_avant;
COMMIT;
""")


def reglages(chemin: Path = REGLAGES) -> Dict[str, Any]:
    """Réglages du fichier TOML complétés par les défauts ; absent ou illisible : défauts."""
    r = dict(DEFAUTS)
    try:
        with open(chemin, "rb") as f:
            lu = tomllib.load(f)
    except FileNotFoundError:
        return r
    except (OSError, tomllib.TOMLDecodeError) as e:
        log.warning("réglages illisibles (%s), défauts appliqués : %s", chemin, e)
        return r
    for cle, defaut in DEFAUTS.items():
        v = lu.get(cle)
        # bool est un int : on compare les types exacts pour ne pas laisser passer true à la place d'un nombre.
        if v is not None and type(v) is type(defaut):
            r[cle] = v
    return r
