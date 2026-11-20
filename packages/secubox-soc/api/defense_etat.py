# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""État SADE persistant (#3839) : mode, seuils, liste blanche, décisions, en SQLite (WAL).

Une connexion par appel (jamais partagée entre fils). Migrations numérotées `migrations/NNNN-nom.sql`,
appliquées au premier usage de façon idempotente. Chemins surchargeables pour les tests :
`SECUBOX_SOC_DEFENSE_DB` et `SECUBOX_AUDIT_LOG` (lus à chaque appel).
"""
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

DB_DEFAUT = "/var/lib/secubox/soc/defense.db"
AUDIT_DEFAUT = "/var/log/secubox/audit.log"
MIGRATIONS = Path(__file__).resolve().parent / "migrations"
_NOM = re.compile(r"^(\d{4})-[\w.-]+\.sql$")

MODES = ("observe", "reactive", "active", "aggressive")
MODES_OUVERTS = ("observe", "reactive")  # active/aggressive attendent les gestes (hors périmètre « chapeau »)

# Liste blanche amorcée, non supprimable : jamais de blocage du réseau local ni de la boucle.
AMORCE = (
    ("10.0.0.0/8", "RFC 1918"), ("172.16.0.0/12", "RFC 1918"), ("192.168.0.0/16", "RFC 1918"),
    ("127.0.0.0/8", "boucle locale"), ("169.254.0.0/16", "lien-local"), ("100.64.0.0/10", "CGNAT"),
    ("::1/128", "boucle locale IPv6"), ("fc00::/7", "ULA IPv6"), ("fe80::/10", "lien-local IPv6"),
)


def _chemin_db() -> str:
    return os.environ.get("SECUBOX_SOC_DEFENSE_DB", DB_DEFAUT)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connecter() -> sqlite3.Connection:
    chemin = _chemin_db()
    Path(chemin).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(chemin, timeout=5, isolation_level=None)
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA busy_timeout = 5000")
    db.execute("PRAGMA synchronous = NORMAL")
    _migrer(db)
    return db


def _migrer(db: sqlite3.Connection) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, appliquee_le TEXT NOT NULL)")
    faites = {v for (v,) in db.execute("SELECT version FROM schema_migrations")}
    for f in sorted(MIGRATIONS.iterdir()):
        m = _NOM.match(f.name)
        if not m or int(m.group(1)) in faites:
            continue
        try:
            db.execute("BEGIN IMMEDIATE")
            # une autre connexion a pu migrer entre-temps
            if db.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (int(m.group(1)),)).fetchone():
                db.execute("COMMIT")
                continue
            for instr in f.read_text(encoding="utf-8").split(";"):
                if "\n".join(l for l in instr.splitlines() if not l.strip().startswith("--")).strip():
                    db.execute(instr)
            if int(m.group(1)) == 1:
                for cidr, motif in AMORCE:
                    db.execute("INSERT OR IGNORE INTO liste_blanche(cidr, motif, par, ts, amorcee) VALUES (?,?,?,?,1)",
                               (cidr, motif, "systeme", _ts()))
            db.execute("INSERT INTO schema_migrations(version, appliquee_le) VALUES (?, ?)", (int(m.group(1)), _ts()))
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise


def mode_courant() -> str:
    with closing(_connecter()) as db:
        r = db.execute("SELECT valeur FROM mode WHERE id = 1").fetchone()
    return r[0] if r else "observe"


def _auditer(ancien: str, nouveau: str, par: str) -> None:
    """Une ligne en ajout seul ; jamais de secret. Un échec d'écriture ne passe pas en silence (exception)."""
    ligne = f"{_ts()} sade-mode ancien={ancien} nouveau={nouveau} operateur={par}\n"
    with open(os.environ.get("SECUBOX_AUDIT_LOG", AUDIT_DEFAUT), "a", encoding="utf-8") as f:
        f.write(ligne)


def changer_mode(valeur: str, par: str) -> None:
    if valeur not in MODES:
        raise ValueError("mode inconnu")
    if valeur not in MODES_OUVERTS:
        raise PermissionError("gestes_non_livres")
    with closing(_connecter()) as db:
        r = db.execute("SELECT valeur FROM mode WHERE id = 1").fetchone()
        ancien = r[0] if r else "observe"
        db.execute("INSERT INTO mode(id, valeur, depuis, par) VALUES (1,?,?,?) "
                   "ON CONFLICT(id) DO UPDATE SET valeur=excluded.valeur, depuis=excluded.depuis, par=excluded.par",
                   (valeur, _ts(), par))
    _auditer(ancien, valeur, par)


def seuils() -> Dict[str, str]:
    with closing(_connecter()) as db:
        return dict(db.execute("SELECT cle, valeur FROM seuils ORDER BY cle").fetchall())


def liste_blanche() -> List[Dict[str, Any]]:
    with closing(_connecter()) as db:
        return [{"cidr": c, "motif": m, "par": p, "ts": t, "supprimable": not a}
                for c, m, p, t, a in db.execute("SELECT cidr, motif, par, ts, amorcee FROM liste_blanche ORDER BY rowid")]
