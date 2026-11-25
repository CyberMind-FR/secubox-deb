# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Stockage des instantanés du paysage (#3921) : zlib(JSON), éclaircissement horaire, budget propre.

Aucun code ne suppose un espacement fixe entre instantanés. Le dernier instantané n'est jamais évincé.
"""
from __future__ import annotations

import json
import sqlite3
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

BUDGET_OCTETS = 60 * 1024 * 1024
FENETRE_FINE_S = 48 * 3600
RETENTION_S = 30 * 86400


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _json(v: Any) -> str:
    return json.dumps(v if v is not None else {}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def ecrire(db: sqlite3.Connection, epoch: float, partiel: bool, graphe: dict, compteurs: dict,
           difference: dict) -> bool:
    ts = _ts(epoch)
    blob = zlib.compress(_json(graphe).encode("utf-8"), 6)
    db.execute("BEGIN IMMEDIATE")
    try:
        ligne = db.execute("SELECT max(epoch) FROM paysage_instantanes").fetchone()
        if ligne[0] is not None and epoch <= ligne[0]:
            db.execute("ROLLBACK")
            return False
        cur = db.execute(
            "INSERT OR IGNORE INTO paysage_instantanes(ts, epoch, partiel, graphe, compteurs_json, difference_json,"
            " octets) VALUES (?,?,?,?,?,?,?)",
            (ts, float(epoch), 1 if partiel else 0, blob, _json(compteurs), _json(difference), len(blob)))
        ok = cur.rowcount == 1
        db.execute("COMMIT" if ok else "ROLLBACK")
        return ok
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def _entete(r: sqlite3.Row) -> Dict[str, Any]:
    return {"ts": r["ts"], "epoch": r["epoch"], "partiel": bool(r["partiel"]),
            "compteurs": json.loads(r["compteurs_json"])}


def dernier(db: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    r = db.execute("SELECT ts FROM paysage_instantanes ORDER BY epoch DESC LIMIT 1").fetchone()
    return lire(db, r["ts"]) if r else None


def lire(db: sqlite3.Connection, ts: str) -> Optional[Dict[str, Any]]:
    r = db.execute("SELECT * FROM paysage_instantanes WHERE ts = ?", (ts,)).fetchone()
    if not r:
        return None
    d = _entete(r)
    d["graphe"] = json.loads(zlib.decompress(r["graphe"]).decode("utf-8"))
    d["difference"] = json.loads(r["difference_json"])
    d["octets"] = r["octets"]
    return d


def chronologie(db: sqlite3.Connection, de: float, a: float) -> List[Dict[str, Any]]:
    return [_entete(r) for r in db.execute(
        "SELECT ts, epoch, partiel, compteurs_json FROM paysage_instantanes WHERE epoch >= ? AND epoch <= ?"
        " ORDER BY epoch", (de, a))]


def eclaircir(db: sqlite3.Connection, maintenant: float) -> int:
    """Retourne le nombre d'instantanés supprimés."""
    supprimes = 0
    db.execute("BEGIN IMMEDIATE")
    try:
        supprimes += db.execute("DELETE FROM paysage_instantanes WHERE epoch < ?",
                                (maintenant - RETENTION_S,)).rowcount
        vus = set()
        a_suppr = []
        for ts, epoch in db.execute("SELECT ts, epoch FROM paysage_instantanes WHERE epoch < ? ORDER BY epoch",
                                    (maintenant - FENETRE_FINE_S,)).fetchall():
            heure = int(epoch // 3600)
            if heure in vus:
                a_suppr.append((ts,))
            vus.add(heure)
        db.executemany("DELETE FROM paysage_instantanes WHERE ts = ?", a_suppr)
        supprimes += len(a_suppr)
        while db.execute("SELECT COALESCE(SUM(octets),0) FROM paysage_instantanes").fetchone()[0] > BUDGET_OCTETS:
            r = db.execute("SELECT ts FROM paysage_instantanes ORDER BY epoch LIMIT 1 OFFSET 0").fetchone()
            if db.execute("SELECT count(*) FROM paysage_instantanes").fetchone()[0] <= 1:
                break
            db.execute("DELETE FROM paysage_instantanes WHERE ts = ?", (r["ts"],))
            supprimes += 1
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return supprimes
