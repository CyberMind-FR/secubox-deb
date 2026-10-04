# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Compteurs par jour, appareil, catégorie et domaine (SQLite, 30 jours). Donnée de navigation : fichier 0640, jamais exportée."""
import os
import sqlite3
import time
from pathlib import Path
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS wf_counts (
  jour TEXT NOT NULL, client TEXT NOT NULL, categorie TEXT NOT NULL, domaine TEXT NOT NULL, n INTEGER NOT NULL,
  PRIMARY KEY (jour, client, categorie, domaine));
CREATE INDEX IF NOT EXISTS wf_counts_jour ON wf_counts (jour);
"""


def _jour(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


class Magasin:
    def __init__(self, chemin):
        self.chemin = Path(chemin)
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        with self._cx() as cx:
            cx.executescript(SCHEMA)
        os.chmod(self.chemin, 0o640)

    def _cx(self):
        cx = sqlite3.connect(self.chemin, timeout=10)
        cx.execute("PRAGMA journal_mode=WAL")
        return cx

    def ajouter(self, lot: Iterable, exclus: set) -> int:
        """`lot` : (Evenement, catégorie). Rend le nombre d'événements comptés (les adresses de la box sont exclues)."""
        n = 0
        with self._cx() as cx:
            for e, cat in lot:
                if e.client in exclus:
                    continue
                cx.execute("INSERT INTO wf_counts (jour, client, categorie, domaine, n) VALUES (?, ?, ?, ?, 1) "
                           "ON CONFLICT (jour, client, categorie, domaine) DO UPDATE SET n = n + 1",
                           (_jour(e.ts), e.client, cat, e.qname))
                n += 1
        return n

    def par_categorie(self, depuis_jour: str) -> dict:
        with self._cx() as cx:
            return {c: int(s) for c, s in cx.execute(
                "SELECT categorie, SUM(n) FROM wf_counts WHERE jour >= ? GROUP BY categorie", (depuis_jour,))}

    def par_client(self, depuis_jour: str) -> dict:
        sortie: dict = {}
        with self._cx() as cx:
            for cl, cat, s in cx.execute(
                    "SELECT client, categorie, SUM(n) FROM wf_counts WHERE jour >= ? GROUP BY client, categorie", (depuis_jour,)):
                sortie.setdefault(cl, {})[cat] = int(s)
        return sortie

    def top_domaines(self, categorie: str, depuis_jour: str, n: int = 50) -> list:
        with self._cx() as cx:
            return [(d, int(s)) for d, s in cx.execute(
                "SELECT domaine, SUM(n) AS s FROM wf_counts WHERE categorie = ? AND jour >= ? GROUP BY domaine "
                "ORDER BY s DESC, domaine LIMIT ?", (categorie, depuis_jour, max(1, min(int(n), 500))))]

    def purger(self, retention_jours: int, maintenant: int | None = None) -> int:
        seuil = _jour((maintenant if maintenant is not None else int(time.time())) - max(1, int(retention_jours)) * 86400)
        with self._cx() as cx:
            return cx.execute("DELETE FROM wf_counts WHERE jour < ?", (seuil,)).rowcount
