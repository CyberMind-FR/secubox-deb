# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Éphéméride :: observations de l'utilisateur — SQLite local, requêtes paramétrées, historique plafonné."""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

TEXTE_MAX = 2000
MAX_DEFAUT = 500
BASE = Path(os.environ.get("SECUBOX_EPH_DB", "/var/lib/secubox/ephemeride/observations.db"))


class ObservationInvalide(ValueError):
    pass


@dataclass
class Observation:
    id: int
    texte: str
    cree: str
    modifie: str


def _maintenant() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _valider(texte) -> str:
    if not isinstance(texte, str) or not texte.strip():
        raise ObservationInvalide("l'observation est vide")
    if len(texte) > TEXTE_MAX:
        raise ObservationInvalide(f"l'observation dépasse {TEXTE_MAX} caractères")
    return texte.strip()


class Observations:
    def __init__(self, chemin: Path = BASE, maximum: int = MAX_DEFAUT):
        self.chemin, self.maximum = Path(chemin), maximum
        self._verrou = threading.Lock()
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._ouvrir()) as c, c:
            c.execute("CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY AUTOINCREMENT, texte TEXT NOT NULL,"
                      " cree TEXT NOT NULL, modifie TEXT NOT NULL)")

    def _ouvrir(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.chemin, timeout=5)
        c.row_factory = sqlite3.Row
        return c

    @staticmethod
    def _obs(r) -> Observation:
        return Observation(r["id"], r["texte"], r["cree"], r["modifie"])

    def ajouter(self, texte: str) -> Observation:
        texte, t = _valider(texte), _maintenant()
        with self._verrou, closing(self._ouvrir()) as c, c:
            cur = c.execute("INSERT INTO observations (texte, cree, modifie) VALUES (?, ?, ?)", (texte, t, t))
            c.execute("DELETE FROM observations WHERE id NOT IN (SELECT id FROM observations ORDER BY id DESC LIMIT ?)",
                      (self.maximum,))
            return self._obs(c.execute("SELECT * FROM observations WHERE id = ?", (cur.lastrowid,)).fetchone())

    def modifier(self, ident: int, texte: str) -> Optional[Observation]:
        texte = _valider(texte)
        with self._verrou, closing(self._ouvrir()) as c, c:
            if not c.execute("UPDATE observations SET texte = ?, modifie = ? WHERE id = ?", (texte, _maintenant(), ident)).rowcount:
                return None
            return self._obs(c.execute("SELECT * FROM observations WHERE id = ?", (ident,)).fetchone())

    def supprimer(self, ident: int) -> bool:
        with self._verrou, closing(self._ouvrir()) as c, c:
            return c.execute("DELETE FROM observations WHERE id = ?", (ident,)).rowcount > 0

    def lister(self, limite: int = 20) -> List[Observation]:
        with closing(self._ouvrir()) as c:
            return [self._obs(r) for r in c.execute("SELECT * FROM observations ORDER BY id DESC LIMIT ?",
                                                    (max(1, min(int(limite), self.maximum)),))]

    def dernier(self) -> Optional[Observation]:
        r = self.lister(1)
        return r[0] if r else None
