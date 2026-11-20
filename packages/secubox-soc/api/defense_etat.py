# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""État SADE persistant (#3839) : mode, seuils, liste blanche, décisions, en SQLite (WAL).

Une connexion par appel (jamais partagée entre fils). Migrations numérotées `migrations/NNNN-nom.sql`,
appliquées au premier usage de façon idempotente. Chemins surchargeables pour les tests :
`SECUBOX_SOC_DEFENSE_DB` et `SECUBOX_AUDIT_LOG` (lus à chaque appel).
"""
import json
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
MODES_OUVERTS = ("observe", "reactive", "active")  # aggressive attend ses gestes (hors périmètre)


def _chemin_db() -> str:
    return os.environ.get("SECUBOX_SOC_DEFENSE_DB", DB_DEFAUT)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connecter() -> sqlite3.Connection:
    chemin = _chemin_db()
    Path(chemin).parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    db = sqlite3.connect(chemin, timeout=5, isolation_level=None)
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA busy_timeout = 5000")
    db.execute("PRAGMA recursive_triggers = ON")  # seconde garde : REPLACE déclenche aussi les triggers DELETE
    db.execute("PRAGMA synchronous = NORMAL")
    _migrer(db)
    for suffixe in ("", "-wal", "-shm"):  # file d'approbation et liste blanche : jamais lisibles par « autres »
        try:
            os.chmod(chemin + suffixe, 0o640)
        except OSError:
            pass  # fichier absent (WAL pas encore créé) ou non possédé : la contrainte vaut au mieux
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


def champ_sain(v: Any, n: int = 256) -> str:
    """Champ d'audit : sans espace ni caractère de contrôle (une ligne = une décision), borné à `n` caractères."""
    return ("".join(c if (c.isprintable() and not c.isspace()) else "_" for c in str(v))[:n]) or "-"


def _operateur_sain(par: str) -> str:
    """Nom d'opérateur pour l'audit : sans caractère de contrôle ni espace (anti-forge de ligne), 64 car. au plus."""
    nettoye = "".join(c if (c.isprintable() and not c.isspace()) else "_" for c in str(par))
    return nettoye[:64] or "inconnu"


def ecrire_audit(corps: str) -> None:
    """Ajoute à l'audit UNE ligne JSON (comme `secubox_core.auth._ecrire_audit` : json.dumps, ensure_ascii=True), flush
    + fsync. Lève `AuditIndisponible` en cas d'échec.

    `corps` = « <action> clé=valeur clé=valeur … » (champs déjà assainis, sans espace) ; l'objet écrit commence par
    `ts` (ISO-8601 UTC), `module: "soc"`, `action` (l'étiquette `sade-*`), `operateur`, puis les autres champs. Un champ
    qui porterait un nom réservé est préfixé `champ_` : il ne masque jamais l'une des quatre clés."""
    action, *champs = corps.replace("\r", "_").replace("\n", "_").split()
    entree: Dict[str, Any] = {"ts": _ts(), "module": "soc", "action": action}
    reste: Dict[str, Any] = {}
    for c in champs:
        cle, sep, val = c.partition("=")
        if not sep or not cle:
            cle, val = "note", c
        if cle in ("ts", "module", "action", "operateur"):
            cle = cle if cle == "operateur" else "champ_" + cle
        (entree if cle == "operateur" else reste)[cle] = val
    entree.setdefault("operateur", "inconnu")
    entree.update(reste)
    ligne = json.dumps(entree, ensure_ascii=True)
    try:
        with open(os.environ.get("SECUBOX_AUDIT_LOG", AUDIT_DEFAUT), "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
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
#
# Une décision est identifiée par l'EMPREINTE de la proposition (geste, adresses, durée), pas par l'acteur. Seule la
# dernière génération d'une empreinte compte. Une décision tranchée se ré-arme (nouvelle génération) quand le ban est
# expiré (`tranche_ts + (ttl_s ou 4 h) + 5 min`) ou quand un refus a plus de 24 h ; son état effectif est alors
# `en_attente`. Une ligne `en_cours` ne se débloque que par `reprendre`, après le délai maximal des appels au WAF.

ETATS_DECISION = ("en_attente", "en_cours", "applique", "refuse")
TTL_DEFAUT_WAF_S = 4 * 3600  # durée par défaut du WAF (`duration` omise : « 4h »)
MARGE_EXPIRATION_S = 5 * 60
REARMEMENT_REFUS_S = 24 * 3600


class ModeRefuse(Exception):
    """Le mode courant n'autorise pas la décision (relu dans la transaction qui la réclame)."""


class DejaTraitee(Exception):
    """La décision est déjà appliquée, refusée ou en cours : jamais deux fois le même geste."""


class PasBloquee(Exception):
    """Reprise refusée : la décision n'est pas `en_cours`, ou pas depuis assez longtemps."""


def _epoch(ts: Optional[str]) -> Optional[float]:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp() if ts else None
    except (TypeError, ValueError):
        return None


def _rearmable(etat: str, tranche_ts: Optional[str], ttl_s: Optional[int], maintenant: float) -> bool:
    t = _epoch(tranche_ts)
    if t is None:
        return False
    if etat == "applique":
        return maintenant > t + (ttl_s or TTL_DEFAUT_WAF_S) + MARGE_EXPIRATION_S
    if etat == "refuse":
        return maintenant > t + REARMEMENT_REFUS_S
    return False


_COLS = ("generation", "menace_id", "cible", "geste", "score", "ttl_s", "etat", "demande_ts", "tranche_ts", "par", "resultat")


def _derniere(db: sqlite3.Connection, empreinte: str) -> Optional[Dict[str, Any]]:
    r = db.execute(f"SELECT {', '.join(_COLS)} FROM decisions WHERE empreinte = ? ORDER BY generation DESC LIMIT 1",
                   (empreinte,)).fetchone()
    return dict(zip(_COLS, r)) if r else None


def _effectif(ligne: Optional[Dict[str, Any]], maintenant: float) -> str:
    if ligne is None:
        return "en_attente"
    if _rearmable(ligne["etat"], ligne["tranche_ts"], ligne["ttl_s"], maintenant):
        return "en_attente"
    return ligne["etat"]


def decision(empreinte: str) -> Dict[str, Any]:
    """Dernière génération d'une empreinte, avec `etat` EFFECTIF (`en_attente` si aucune ligne ou si ré-armable) et
    `etat_enregistre` (valeur en base, None sans ligne)."""
    try:
        with closing(_connecter()) as db:
            ligne = _derniere(db, empreinte)
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    out = dict(ligne) if ligne else {c: None for c in _COLS}
    out["etat_enregistre"] = ligne["etat"] if ligne else None
    out["etat"] = _effectif(ligne, datetime.now(timezone.utc).timestamp())
    return out


def etats_decisions() -> Dict[str, str]:
    """{empreinte: état effectif de la dernière génération}."""
    maintenant = datetime.now(timezone.utc).timestamp()
    try:
        with closing(_connecter()) as db:
            lignes = db.execute(
                "SELECT d.empreinte, d.etat, d.tranche_ts, d.ttl_s FROM decisions d JOIN "
                "(SELECT empreinte, MAX(generation) g FROM decisions GROUP BY empreinte) m "
                "ON d.empreinte = m.empreinte AND d.generation = m.g").fetchall()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return {e: ("en_attente" if _rearmable(et, t, ttl, maintenant) else et) for e, et, t, ttl in lignes}


class Reclamation(int):
    """Génération réclamée (un entier) portant l'horodatage `demande_ts` de la réclamation, pour `conclure`."""
    demande_ts: Optional[str] = None


def reclamer(empreinte: str, menace_id: str, geste: str, cible: str, score: Optional[int], ttl_s: Optional[int],
             par: str, etat: str, ligne_audit: str, modes: Tuple[str, ...] = ("reactive",)) -> int:
    """Réclame une décision (`en_cours` avant un geste, ou `refuse`) dans UNE transaction BEGIN IMMEDIATE : relit le
    mode (doit être l'un de `modes`, `reactive` par défaut), prend la dernière génération de l'empreinte — aucune : INSERT génération 1 ;
    `en_attente` : reprise ; tranchée et ré-armable : INSERT génération + 1 (contrainte UNIQUE (empreinte, generation)) ;
    sinon `DejaTraitee` —, écrit l'audit (flush + fsync, suffixé de la génération) PUIS valide. Audit en échec :
    ROLLBACK, rien n'est réclamé. Rend la génération réclamée."""
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
            if (r[0] if r else "observe") not in modes:
                db.execute("ROLLBACK")
                raise ModeRefuse(r[0] if r else "observe")
            ligne = _derniere(db, empreinte)
            maintenant = datetime.now(timezone.utc).timestamp()
            demande = _ts()
            tranche = demande if etat == "refuse" else None
            if ligne is not None and ligne["etat"] == "en_attente":
                gen = ligne["generation"]
                db.execute("UPDATE decisions SET etat = ?, menace_id = ?, cible = ?, score = ?, ttl_s = ?, demande_ts = ?, "
                           "tranche_ts = ?, par = ?, resultat = NULL "
                           "WHERE empreinte = ? AND generation = ? AND etat = 'en_attente'",
                           (etat, menace_id, cible, score, ttl_s, demande, tranche, par, empreinte, gen))
            elif ligne is None or _rearmable(ligne["etat"], ligne["tranche_ts"], ligne["ttl_s"], maintenant):
                gen = 1 if ligne is None else ligne["generation"] + 1
                # l'INSERT tranche le double clic : un second INSERT concurrent heurterait la contrainte UNIQUE
                db.execute("INSERT INTO decisions(empreinte, generation, menace_id, cible, geste, score, ttl_s, etat, "
                           "demande_ts, tranche_ts, par) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (empreinte, gen, menace_id, cible, geste, score, ttl_s, etat, demande, tranche, par))
            else:
                db.execute("ROLLBACK")
                raise DejaTraitee(ligne["etat"])
            ecrire_audit(f"{ligne_audit} generation={gen}")
            db.execute("COMMIT")
            rec = Reclamation(gen)
            rec.demande_ts = demande
            return rec
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


def bans_auto_depuis(secondes: int, maintenant: Optional[float] = None) -> int:
    """Nombre d'ADRESSES réclamées par l'exécuteur automatique (`par = 'sade-auto'`) dont la demande tombe dans les
    `secondes` dernières secondes, QUEL QUE SOIT l'état de la décision (`applique`, `en_cours`, `en_attente`, `refuse`) :
    une décision partielle a pu bannir une partie de ses adresses, et un plafond surcompte plutôt que de sous-compter.
    Les décisions des autres opérateurs ne comptent pas. `cible` est une liste d'adresses séparées par `,`."""
    fin = maintenant if maintenant is not None else datetime.now(timezone.utc).timestamp()
    debut = datetime.fromtimestamp(fin - secondes, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with closing(_connecter()) as db:
            lignes = db.execute("SELECT cible FROM decisions WHERE par = 'sade-auto' AND demande_ts >= ?",
                                (debut,)).fetchall()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return sum(len([a for a in (lg[0] or "").split(",") if a.strip()]) for lg in lignes)


def refuse_par_humain(empreinte: str) -> bool:
    """Vrai si une décision de l'empreinte, toutes générations confondues, a été REFUSÉE par un autre opérateur que
    l'exécuteur automatique. Un « non » humain lie le chemin automatique pour toujours, même après le ré-armement de
    24 h (la proposition reste approuvable à la main). Lève `EtatIndisponible` si la base ne se lit pas."""
    try:
        with closing(_connecter()) as db:
            r = db.execute("SELECT 1 FROM decisions WHERE empreinte = ? AND etat = 'refuse' AND par != 'sade-auto' LIMIT 1",
                           (empreinte,)).fetchone()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return r is not None


def conclure(empreinte: str, generation: int, etat: str, resultat: str, demande_ts: Optional[str] = None) -> None:
    """Tranche une décision `en_cours` : `applique`, `refuse` (l'exécuteur automatique, quand `wafctl` a refusé une
    adresse : ré-armable après 24 h, jamais retenté à chaque passage), ou retour `en_attente` après un échec transitoire
    du WAF. Avec `demande_ts` (celui de la réclamation close), un fil retardataire ne peut pas clore une réclamation
    ultérieure de la même génération (reprise)."""
    if etat not in ("applique", "refuse", "en_attente"):
        raise ValueError("état de conclusion inconnu")
    try:
        with closing(_connecter()) as db:
            sql = ("UPDATE decisions SET etat = ?, resultat = ?, tranche_ts = ? "
                   "WHERE empreinte = ? AND generation = ? AND etat = 'en_cours'")
            args: list = [etat, resultat[:500], _ts() if etat in ("applique", "refuse") else None, empreinte, generation]
            if demande_ts is not None:
                sql += " AND demande_ts = ?"
                args.append(demande_ts)
            db.execute(sql, args)
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e


def reprendre(empreinte: str, par: str, delai_par_adresse_s: float, marge_s: float = 60.0) -> Dict[str, Any]:
    """Ramène une décision `en_cours` à `en_attente`, seulement si sa demande date de plus de
    `nb_adresses × delai_par_adresse_s + marge_s` (aucun appel au WAF ne peut plus être en vol). BEGIN IMMEDIATE ;
    ligne d'audit `sade-reprise` écrite (fsync) AVANT le COMMIT. Sinon `PasBloquee`."""
    try:
        db = _connecter()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    with closing(db):
        try:
            db.execute("BEGIN IMMEDIATE")
            ligne = _derniere(db, empreinte)
            if ligne is None or ligne["etat"] != "en_cours":
                db.execute("ROLLBACK")
                raise PasBloquee("pas en cours")
            n = len([a for a in (ligne["cible"] or "").split(",") if a]) or 1
            debut = _epoch(ligne["demande_ts"])
            age = datetime.now(timezone.utc).timestamp() - debut if debut is not None else None
            seuil = n * delai_par_adresse_s + marge_s
            if age is None or age <= seuil:
                db.execute("ROLLBACK")
                raise PasBloquee(f"demande trop récente ({int(age or 0)} s ≤ {int(seuil)} s)")
            db.execute("UPDATE decisions SET etat = 'en_attente', resultat = ? WHERE empreinte = ? AND generation = ? "
                       "AND etat = 'en_cours'", (f"reprise par {_operateur_sain(par)}", empreinte, ligne["generation"]))
            ecrire_audit(f"sade-reprise empreinte={empreinte} generation={ligne['generation']} "
                         f"acteur={champ_sain(ligne['menace_id'], 16)} adresses={champ_sain(ligne['cible'], 1024)} "
                         f"age_s={int(age)} operateur={_operateur_sain(par)}")
            db.execute("COMMIT")
            return {"generation": ligne["generation"], "age_s": int(age)}
        except (AuditIndisponible, PasBloquee):
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        except sqlite3.Error as e:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise EtatIndisponible(e.__class__.__name__) from e
