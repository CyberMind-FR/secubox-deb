# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Historique SQLite (mode WAL) : relevés et états des services, rétention bornée.

Écritures transactionnelles par le collecteur seul ; l'API ouvre la base en lecture seule (`mode=ro`).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .normalise import pire

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY, hostname TEXT, architecture TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    node_id TEXT NOT NULL, sequence INTEGER NOT NULL, collected_at TEXT NOT NULL, overall TEXT NOT NULL,
    document TEXT NOT NULL, PRIMARY KEY (node_id, sequence)
);
CREATE INDEX IF NOT EXISTS snapshots_quand ON snapshots (node_id, collected_at);
CREATE TABLE IF NOT EXISTS services (
    node_id TEXT NOT NULL, service_id TEXT NOT NULL, collected_at TEXT NOT NULL, status TEXT NOT NULL,
    sleeping INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS services_quand ON services (service_id, collected_at);
CREATE INDEX IF NOT EXISTS services_noeud ON services (node_id, collected_at);
"""


def ouvrir(chemin: Path) -> sqlite3.Connection:
    cx = sqlite3.connect(str(chemin), timeout=10)
    cx.execute("PRAGMA journal_mode=WAL")
    cx.execute("PRAGMA synchronous=NORMAL")
    cx.executescript(SCHEMA)
    return cx


def ouvrir_lecture(chemin: Path) -> Optional[sqlite3.Connection]:
    if not chemin.exists():
        return None
    cx = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True, timeout=5)
    cx.row_factory = sqlite3.Row
    return cx


def sequence_suivante(cx: sqlite3.Connection, noeud: str) -> int:
    r = cx.execute("SELECT MAX(sequence) FROM snapshots WHERE node_id = ?", (noeud,)).fetchone()
    return (r[0] or 0) + 1


def inscrire(cx: sqlite3.Connection, releve: Dict[str, Any], detail: List[Dict[str, Any]]) -> None:
    n, quand = releve["node"], releve["collected_at"]
    with cx:
        cx.execute(
            "INSERT INTO nodes (id, hostname, architecture, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET hostname = excluded.hostname, architecture = excluded.architecture, "
            "last_seen = excluded.last_seen",
            (n["id"], n.get("hostname"), n.get("architecture"), quand, quand))
        cx.execute("INSERT INTO snapshots (node_id, sequence, collected_at, overall, document) VALUES (?, ?, ?, ?, ?)",
                   (n["id"], releve["sequence"], quand, releve["health"]["overall"],
                    json.dumps(releve, separators=(",", ":"), allow_nan=False)))
        cx.executemany("INSERT INTO services (node_id, service_id, collected_at, status, sleeping) VALUES (?, ?, ?, ?, ?)",
                       [(n["id"], d["id"], quand, d["status"], int(d["sleeping"])) for d in detail])


def purger(cx: sqlite3.Connection, jours: int, maintenant: Optional[datetime] = None) -> None:
    limite = ((maintenant or datetime.now(timezone.utc)) - timedelta(days=max(1, int(jours)))).isoformat()
    with cx:
        cx.execute("DELETE FROM snapshots WHERE collected_at < ?", (limite,))
        cx.execute("DELETE FROM services WHERE collected_at < ?", (limite,))


def heures(cx: sqlite3.Connection, noeud: str, n: int = 24, maintenant: Optional[datetime] = None) -> List[Dict[str, str]]:
    """Une case par heure, de la plus ancienne à l'actuelle : pire état observé, `unknown` sans relevé."""
    fin = (maintenant or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    debut = fin - timedelta(hours=n)
    cases: Dict[str, List[str]] = {}
    for quand, etat in cx.execute(
            "SELECT collected_at, overall FROM snapshots WHERE node_id = ? AND collected_at >= ? AND collected_at < ?",
            (noeud, debut.isoformat(), fin.isoformat())):
        cases.setdefault(quand[:13], []).append(etat)
    sortie = []
    for i in range(n):
        h = debut + timedelta(hours=i)
        cle = h.isoformat()[:13]
        sortie.append({"hour": h.isoformat(), "status": pire(cases.get(cle, []))})
    return sortie


def disponibilite(cx: sqlite3.Connection, noeud: str, jours: int,
                  maintenant: Optional[datetime] = None) -> Optional[float]:
    """Part des relevés `operational` parmi les relevés CONNUS (spec §8) ; None sans aucun relevé connu."""
    debut = ((maintenant or datetime.now(timezone.utc)) - timedelta(days=jours)).isoformat()
    r = cx.execute(
        "SELECT SUM(overall = 'operational'), SUM(overall NOT IN ('unknown', 'maintenance')) "
        "FROM snapshots WHERE node_id = ? AND collected_at >= ?", (noeud, debut)).fetchone()
    if not r or not r[1]:
        return None
    return round(100.0 * (r[0] or 0) / r[1], 2)
