# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Magasin des lectures évolutives (#4058, Task 4).

Chaque rédaction validée d'un sujet (`"<genre>/<ident>"`) laisse ici son dossier de faits et ses phrases gardées par
le vérificateur ; la tâche des évolutions compare le dossier courant au dernier dossier validé. SQLite, un seul
fichier, aucune adresse : les dossiers de gk2 n'en contiennent pas (vérifié côté gk2 par `rapports.py`).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS interpretations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sujet TEXT NOT NULL, quand INTEGER NOT NULL, phrase TEXT NOT NULL,
    statut TEXT NOT NULL CHECK (statut IN ('verifiee', 'hypothese')), empreinte TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS interpretations_sujet ON interpretations (sujet, quand);
CREATE TABLE IF NOT EXISTS dossiers (
    sujet TEXT NOT NULL, empreinte TEXT NOT NULL, quand INTEGER NOT NULL, contenu TEXT NOT NULL,
    PRIMARY KEY (sujet, empreinte));
"""


def empreinte(dossier: Dict[str, Any]) -> str:
    """Comme `rapports.signature` de gk2 : sha256 du JSON trié, 16 caractères."""
    return hashlib.sha256(json.dumps(dossier, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def _statut(g: Dict[str, Any]) -> str:
    return "hypothese" if g.get("statut") == "hypothese" else "verifiee"


class Magasin:
    def __init__(self, chemin: Path, maintenant: Callable[[], float] = time.time) -> None:
        self.chemin = Path(chemin)
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        self._maintenant = maintenant
        with self._cnx() as c:
            c.executescript(SCHEMA)

    def _cnx(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.chemin, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def _retenir(self, c: sqlite3.Connection, sujet: str, dossier: Dict[str, Any], gardees: List[Dict[str, Any]]) -> bool:
        e = empreinte(dossier)
        quand = int(self._maintenant())
        cur = c.execute("INSERT OR IGNORE INTO dossiers (sujet, empreinte, quand, contenu) VALUES (?, ?, ?, ?)",
                        (sujet, e, quand, json.dumps(dossier, ensure_ascii=False)))
        if not cur.rowcount:
            return False    # même dossier déjà retenu : rien de neuf
        c.executemany("INSERT INTO interpretations (sujet, quand, phrase, statut, empreinte) VALUES (?, ?, ?, ?, ?)",
                      [(sujet, quand, g["texte"], _statut(g), e) for g in gardees
                       if isinstance(g, dict) and isinstance(g.get("texte"), str) and g.get("statut") != "retiree"])
        return True

    def retenir(self, sujet: str, dossier: Dict[str, Any], gardees: List[Dict[str, Any]]) -> None:
        with self._cnx() as c:
            self._retenir(c, sujet, dossier, gardees)

    def dernier_valide(self, sujet: str) -> Optional[Dict[str, Any]]:
        with self._cnx() as c:
            r = c.execute("SELECT contenu FROM dossiers WHERE sujet = ? ORDER BY quand DESC, rowid DESC LIMIT 1",
                          (sujet,)).fetchone()
        return json.loads(r["contenu"]) if r else None

    def interpretations(self, sujet: str) -> List[Dict[str, Any]]:
        with self._cnx() as c:
            rs = c.execute("SELECT id, sujet, quand, phrase, statut, empreinte FROM interpretations WHERE sujet = ? "
                           "ORDER BY quand, id", (sujet,)).fetchall()
        return [dict(r) for r in rs]

    def amorcer(self, rapports: List[Dict[str, Any]]) -> int:
        """Reprend les lectures IA déjà vérifiées sur gk2 (réponses de `GET /rapports/{genre}/{id}` : `ia.etat` « fait »
        — « ia » accepté — et non périmée). Idempotent : retourne le nombre de dossiers nouvellement retenus."""
        n = 0
        with self._cnx() as c:
            for r in rapports:
                ia, d = (r or {}).get("ia"), (r or {}).get("dossier")
                if not isinstance(ia, dict) or not isinstance(d, dict) or ia.get("etat") not in ("fait", "ia") \
                        or ia.get("perimee"):
                    continue
                s = d.get("sujet") or {}
                if not (isinstance(s.get("genre"), str) and isinstance(s.get("id"), str)):
                    continue
                n += self._retenir(c, f"{s['genre']}/{s['id']}", d, ia.get("gardees") or [])
        return n
