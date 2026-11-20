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
from typing import Any, Dict, List, Optional, Tuple

DB_DEFAUT = "/var/lib/secubox/soc/defense.db"
AUDIT_DEFAUT = "/var/log/secubox/audit.log"
MIGRATIONS = Path(__file__).resolve().parent / "migrations"
_NOM = re.compile(r"^(\d{4})-[\w.-]+\.sql$")

MODES = ("observe", "reactive", "active", "aggressive")
MODES_OUVERTS = ("observe", "reactive")  # active/aggressive attendent les gestes (hors périmètre « chapeau »)


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
    db.execute("PRAGMA recursive_triggers = ON")  # seconde garde : REPLACE déclenche aussi les triggers DELETE
    db.execute("PRAGMA synchronous = NORMAL")
    _migrer(db)
    return db


def _migrer(db: sqlite3.Connection) -> None:
    """Applique les migrations manquantes. Chaque script est idempotent (IF NOT EXISTS / INSERT OR IGNORE)
    et s'exécute dans sa propre transaction : deux processus qui migrent ensemble convergent."""
    db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, appliquee_le TEXT NOT NULL)")
    faites = {v for (v,) in db.execute("SELECT version FROM schema_migrations")}
    for f in sorted(MIGRATIONS.iterdir()):
        m = _NOM.match(f.name)
        if not m or int(m.group(1)) in faites:
            continue
        script = ("BEGIN IMMEDIATE;\n" + f.read_text(encoding="utf-8") +
                  f"\nINSERT OR IGNORE INTO schema_migrations(version, appliquee_le) VALUES ({int(m.group(1))}, '{_ts()}');\nCOMMIT;")
        try:
            db.executescript(script)
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise


class EtatIndisponible(Exception):
    """Base illisible ou non inscriptible (répertoire absent, droits)."""


class AuditIndisponible(Exception):
    """L'audit n'a pu être écrit : le changement de mode est annulé (échec fermé)."""


def mode_courant() -> str:
    try:
        with closing(_connecter()) as db:
            r = db.execute("SELECT valeur FROM mode WHERE id = 1").fetchone()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return r[0] if r else "observe"


def _operateur_sain(par: str) -> str:
    """Nom d'opérateur pour l'audit : sans caractère de contrôle ni espace (anti-forge de ligne), 64 car. au plus."""
    nettoye = "".join(c if (c.isprintable() and not c.isspace()) else "_" for c in str(par))
    return nettoye[:64] or "inconnu"


def ecrire_audit(corps: str) -> None:
    """Ajoute une ligne horodatée à l'audit, flush + fsync. Lève `AuditIndisponible` en cas d'échec.
    `corps` doit être fait de champs déjà assainis : les sauts de ligne y sont neutralisés en dernier recours."""
    ligne = f"{_ts()} " + corps.replace("\r", "_").replace("\n", "_") + "\n"
    try:
        with open(os.environ.get("SECUBOX_AUDIT_LOG", AUDIT_DEFAUT), "a", encoding="utf-8") as f:
            f.write(ligne)
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        raise AuditIndisponible(e.__class__.__name__) from e


def changer_mode(valeur: str, par: str) -> None:
    """Change le mode ET écrit sa ligne d'audit dans la même transaction (BEGIN IMMEDIATE) : l'audit est écrit,
    flush + fsync, AVANT le COMMIT ; s'il échoue, ROLLBACK (le mode ne change jamais sans trace)."""
    if valeur not in MODES:
        raise ValueError("mode inconnu")
    if valeur not in MODES_OUVERTS:
        raise PermissionError("gestes_non_livres")
    try:
        db = _connecter()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    with closing(db):
        try:
            db.execute("BEGIN IMMEDIATE")
            r = db.execute("SELECT valeur FROM mode WHERE id = 1").fetchone()
            ancien = r[0] if r else "observe"
            if ancien == valeur:
                db.execute("ROLLBACK")
                return
            db.execute("INSERT INTO mode(id, valeur, depuis, par) VALUES (1,?,?,?) "
                       "ON CONFLICT(id) DO UPDATE SET valeur=excluded.valeur, depuis=excluded.depuis, par=excluded.par",
                       (valeur, _ts(), par))
            operateur = _operateur_sain(par)
            ecrire_audit(f"sade-mode ancien={ancien} nouveau={valeur} operateur={operateur}")
            db.execute("COMMIT")
        except AuditIndisponible:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        except sqlite3.Error as e:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise EtatIndisponible(e.__class__.__name__) from e


def seuils() -> Dict[str, str]:
    with closing(_connecter()) as db:
        return dict(db.execute("SELECT cle, valeur FROM seuils ORDER BY cle").fetchall())


def liste_blanche() -> List[Dict[str, Any]]:
    with closing(_connecter()) as db:
        return [{"cidr": c, "motif": m, "par": p, "ts": t, "supprimable": not a}
                for c, m, p, t, a in db.execute("SELECT cidr, motif, par, ts, amorcee FROM liste_blanche ORDER BY rowid")]


# ── décisions de la file d'approbation (REACTIVE) ────────────────────────────────────────────────

ETATS_DECISION = ("en_attente", "en_cours", "applique", "refuse")


class ModeRefuse(Exception):
    """Le mode courant n'autorise pas la décision (relu dans la transaction qui la réclame)."""


class DejaTraitee(Exception):
    """La décision est déjà appliquée, refusée ou en cours : jamais deux fois le même geste."""


def _cle_decision(decision_id: str):
    menace_id, _, geste = str(decision_id).partition(":")
    return menace_id, geste


def decision(decision_id: str) -> Optional[Dict[str, Any]]:
    """Ligne `decisions` d'un identifiant `ACT-NNNN:geste`, ou un état `en_attente` implicite si aucune ligne."""
    menace_id, geste = _cle_decision(decision_id)
    try:
        with closing(_connecter()) as db:
            r = db.execute("SELECT etat, cible, score, demande_ts, tranche_ts, par, resultat FROM decisions "
                           "WHERE menace_id = ? AND geste = ?", (menace_id, geste)).fetchone()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    if r is None:
        return {"etat": "en_attente", "cible": None, "score": None, "demande_ts": None, "tranche_ts": None,
                "par": None, "resultat": None}
    return dict(zip(("etat", "cible", "score", "demande_ts", "tranche_ts", "par", "resultat"), r))


def etats_decisions() -> Dict[Tuple[str, str], str]:
    """{(menace_id, geste): etat} de toutes les décisions enregistrées."""
    try:
        with closing(_connecter()) as db:
            return {(m, g): e for m, g, e in db.execute("SELECT menace_id, geste, etat FROM decisions")}
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e


def reclamer(menace_id: str, geste: str, cible: str, score: Optional[int], par: str, etat: str,
             ligne_audit: str) -> None:
    """Réclame une décision (`en_cours` avant un geste, ou `refuse`) dans UNE transaction BEGIN IMMEDIATE :
    relit le mode (doit être `reactive`), refuse une décision déjà tranchée ou en cours, pose la ligne par INSERT sous
    la contrainte UNIQUE (menace_id, geste) — ou la reprend si elle était revenue `en_attente` après un échec —, écrit
    l'audit (flush + fsync) PUIS valide. Audit en échec : ROLLBACK, rien n'est réclamé."""
    if etat not in ("en_cours", "refuse"):
        raise ValueError("état de réclamation inconnu")
    try:
        db = _connecter()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    with closing(db):
        try:
            db.execute("BEGIN IMMEDIATE")
            r = db.execute("SELECT valeur FROM mode WHERE id = 1").fetchone()
            if (r[0] if r else "observe") != "reactive":
                db.execute("ROLLBACK")
                raise ModeRefuse(r[0] if r else "observe")
            ex = db.execute("SELECT etat FROM decisions WHERE menace_id = ? AND geste = ?",
                            (menace_id, geste)).fetchone()
            if ex is None:
                # l'INSERT tranche le double clic : un second INSERT concurrent heurterait la contrainte UNIQUE
                db.execute("INSERT INTO decisions(menace_id, cible, geste, score, etat, demande_ts, tranche_ts, par) "
                           "VALUES (?,?,?,?,?,?,?,?)",
                           (menace_id, cible, geste, score, etat, _ts(), _ts() if etat == "refuse" else None, par))
            elif ex[0] == "en_attente":
                db.execute("UPDATE decisions SET etat = ?, cible = ?, score = ?, demande_ts = ?, tranche_ts = ?, par = ?, "
                           "resultat = NULL WHERE menace_id = ? AND geste = ? AND etat = 'en_attente'",
                           (etat, cible, score, _ts(), _ts() if etat == "refuse" else None, par, menace_id, geste))
            else:
                db.execute("ROLLBACK")
                raise DejaTraitee(ex[0])
            ecrire_audit(ligne_audit)
            db.execute("COMMIT")
        except (AuditIndisponible, ModeRefuse, DejaTraitee):
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as e:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise DejaTraitee("en_cours") from e
        except sqlite3.Error as e:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise EtatIndisponible(e.__class__.__name__) from e


def conclure(menace_id: str, geste: str, etat: str, resultat: str) -> None:
    """Tranche une décision `en_cours` : `applique`, ou retour `en_attente` après un échec du WAF."""
    if etat not in ("applique", "en_attente"):
        raise ValueError("état de conclusion inconnu")
    try:
        with closing(_connecter()) as db:
            db.execute("UPDATE decisions SET etat = ?, resultat = ?, tranche_ts = ? "
                       "WHERE menace_id = ? AND geste = ? AND etat = 'en_cours'",
                       (etat, resultat[:500], _ts() if etat == "applique" else None, menace_id, geste))
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
