# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Compteurs par jour, appareil, catégorie et domaine (SQLite, 30 jours). Donnée de navigation : fichier 0640, jamais exportée."""
import contextlib
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS wf_counts (
  jour TEXT NOT NULL, client TEXT NOT NULL, categorie TEXT NOT NULL, domaine TEXT NOT NULL, decision TEXT NOT NULL DEFAULT 'observe', n INTEGER NOT NULL,
  PRIMARY KEY (jour, client, categorie, domaine, decision));
CREATE INDEX IF NOT EXISTS wf_counts_jour ON wf_counts (jour);
CREATE TABLE IF NOT EXISTS wf_meta (cle TEXT PRIMARY KEY, valeur INTEGER NOT NULL);
"""
DECISIONS = ("observe", "bloque")                      # « aurait bloqué » ou « bloqué »
MAX_LIGNES = 500_000                                   # plafond de clés (jour, appareil, catégorie, entrée) : la base ne peut pas remplir le disque


def _jour(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


class Magasin:
    def __init__(self, chemin, max_lignes: int = MAX_LIGNES):
        self.chemin = Path(chemin)
        self.max_lignes = max_lignes
        self._averti = False
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        with self._cx() as cx:
            colonnes = [r[1] for r in cx.execute("PRAGMA table_info(wf_counts)")]
            if colonnes and "decision" not in colonnes:                 # base de la phase 1 : les lignes existantes restent « observe »
                cx.executescript("""ALTER TABLE wf_counts RENAME TO wf_counts_p1;
                    CREATE TABLE wf_counts (jour TEXT NOT NULL, client TEXT NOT NULL, categorie TEXT NOT NULL, domaine TEXT NOT NULL,
                      decision TEXT NOT NULL DEFAULT 'observe', n INTEGER NOT NULL, PRIMARY KEY (jour, client, categorie, domaine, decision));
                    INSERT INTO wf_counts (jour, client, categorie, domaine, decision, n) SELECT jour, client, categorie, domaine, 'observe', n FROM wf_counts_p1;
                    DROP TABLE wf_counts_p1;""")
            cx.executescript(SCHEMA)
        os.chmod(self.chemin, 0o640)

    @contextlib.contextmanager
    def _cx(self):
        cx = sqlite3.connect(self.chemin, timeout=10)
        try:
            cx.execute("PRAGMA journal_mode=WAL")
            cx.execute("PRAGMA secure_delete=ON")        # une ligne purgée est effacée des pages, pas seulement déréférencée
            with cx:
                yield cx
        finally:
            cx.close()

    def ajouter(self, lot: Iterable, exclus: set) -> int:
        """`lot` : (Evenement, catégorie) ; `Evenement.qname` porte l'entrée de liste. Rend le nombre d'événements comptés (les adresses de la
        box sont exclues ; une NOUVELLE clé au-delà du plafond est ignorée, une clé déjà connue est toujours comptée)."""
        n, dernier = 0, 0
        with self._cx() as cx:
            lignes = cx.execute("SELECT COUNT(*) FROM wf_counts").fetchone()[0]
            for item in lot:
                e, cat = item[0], item[1]
                dec = item[2] if len(item) > 2 and item[2] in DECISIONS else "observe"
                if e.client in exclus:
                    continue
                cle = (_jour(e.ts), e.client, cat, e.qname, dec)
                existe = cx.execute("SELECT 1 FROM wf_counts WHERE jour=? AND client=? AND categorie=? AND domaine=? AND decision=?", cle).fetchone()
                if not existe:
                    if lignes >= self.max_lignes:
                        if not self._averti:
                            print(f"secubox-webfilter : plafond de {self.max_lignes} lignes atteint, nouvelles clés ignorées", file=sys.stderr)
                            self._averti = True
                        continue
                    lignes += 1
                cx.execute("INSERT INTO wf_counts (jour, client, categorie, domaine, decision, n) VALUES (?, ?, ?, ?, ?, 1) "
                           "ON CONFLICT (jour, client, categorie, domaine, decision) DO UPDATE SET n = n + 1", cle)
                n += 1
                dernier = max(dernier, e.ts)
            if dernier:
                cx.execute("INSERT INTO wf_meta (cle, valeur) VALUES ('dernier_evenement', ?) "
                           "ON CONFLICT (cle) DO UPDATE SET valeur = MAX(valeur, excluded.valeur)", (dernier,))
        return n

    def dernier_evenement(self) -> int | None:
        with self._cx() as cx:
            r = cx.execute("SELECT valeur FROM wf_meta WHERE cle = 'dernier_evenement'").fetchone()
        return int(r[0]) if r else None

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

    def par_categorie_decision(self, depuis_jour: str) -> dict:
        sortie: dict = {}
        with self._cx() as cx:
            for cat, dec, s in cx.execute("SELECT categorie, decision, SUM(n) FROM wf_counts WHERE jour >= ? GROUP BY categorie, decision", (depuis_jour,)):
                sortie.setdefault(cat, {})[dec] = int(s)
        return sortie

    def par_client_decision(self, depuis_jour: str) -> dict:
        sortie: dict = {}
        with self._cx() as cx:
            for cl, cat, dec, s in cx.execute(
                    "SELECT client, categorie, decision, SUM(n) FROM wf_counts WHERE jour >= ? GROUP BY client, categorie, decision", (depuis_jour,)):
                sortie.setdefault(cl, {}).setdefault(cat, {})[dec] = int(s)
        return sortie

    def top_domaines(self, categorie: str, depuis_jour: str, n: int = 50) -> list:
        with self._cx() as cx:
            return [(d, int(s)) for d, s in cx.execute(
                "SELECT domaine, SUM(n) AS s FROM wf_counts WHERE categorie = ? AND jour >= ? GROUP BY domaine "
                "ORDER BY s DESC, domaine LIMIT ?", (categorie, depuis_jour, max(1, min(int(n), 500))))]

    def purger(self, retention_jours: int, maintenant: int | None = None) -> int:
        seuil = _jour((maintenant if maintenant is not None else int(time.time())) - max(1, int(retention_jours)) * 86400)
        with self._cx() as cx:
            n = cx.execute("DELETE FROM wf_counts WHERE jour < ?", (seuil,)).rowcount
        with self._cx() as cx:
            cx.execute("PRAGMA wal_checkpoint(TRUNCATE)")             # l'historique purgé ne survit pas dans le journal WAL
        return n
