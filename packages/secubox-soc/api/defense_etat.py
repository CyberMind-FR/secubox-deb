# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""État SADE persistant (#3839) : mode, seuils, liste blanche, décisions, en SQLite (WAL).

Une connexion par appel (jamais partagée entre fils). Migrations numérotées `migrations/NNNN-nom.sql`,
appliquées au premier usage de façon idempotente. Chemins surchargeables pour les tests :
`SECUBOX_SOC_DEFENSE_DB` et `SECUBOX_AUDIT_LOG` (lus à chaque appel).
"""
import ipaddress
import json
import logging
import unicodedata
import os
import re
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DB_DEFAUT = "/var/lib/secubox/soc/defense.db"
#: Mode et liste blanche publiés pour l'API du WAF de gk2 (#3723), qui ne lit jamais la base du SOC.
FICHIER_SADE_DEFAUT = "/run/secubox/sade-mode.json"
AUDIT_DEFAUT = "/var/log/secubox/audit.log"
MIGRATIONS = Path(__file__).resolve().parent / "migrations"
_NOM = re.compile(r"^(\d{4})-[\w.-]+\.sql$")

MODES = ("observe", "reactive", "active", "aggressive")
MODES_OUVERTS = ("observe", "reactive", "active")  # aggressive : banc seulement, ouverture sur accord du propriétaire

log = logging.getLogger("secubox.soc.defense_etat")


def _chemin_db() -> str:
    return os.environ.get("SECUBOX_SOC_DEFENSE_DB", DB_DEFAUT)


def _chemin_fichier_sade() -> str:
    return os.environ.get("SECUBOX_SOC_SADE_MODE", FICHIER_SADE_DEFAUT)


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


def mode_detail() -> Tuple[str, Optional[str], Optional[str]]:
    """(valeur, depuis, par) du mode ; sans ligne : (`observe`, None, None). Lève `EtatIndisponible`."""
    try:
        with closing(_connecter()) as db:
            r = db.execute("SELECT valeur, depuis, par FROM mode WHERE id = 1").fetchone()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return (r[0], r[1], r[2]) if r else ("observe", None, None)


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
    publier_mode()


# ── publication du mode pour gk2 (#3723) ──────────────────────────────────────────────────────────
# `/run/secubox/sade-mode.json` = {"mode", "depuis", "liste_blanche"} : `depuis` est l'instant de CETTE publication
# (le battement de l'API la refait toutes les `BATTEMENT_SADE_S`), jamais celui du changement de mode. L'API du WAF
# tient pour `observe` un fichier daté de plus de 15 min : un SOC arrêté ferme l'automatique de lui-même. Écriture par
# renommage atomique (temporaire du même dossier, fsync, `os.replace`) en 0644 : gk2 ne voit jamais un fichier partiel.
# Jamais levée : le mode et la liste font foi dans la base ; un échec de publication est journalisé, le battement
# suivant le rattrape. Base illisible : RIEN n'est publié (jamais un mode ni une liste inventés ; le fichier vieillit).

#: Dernière cause d'échec de publication signalée (clé « cause ») : une ligne d'audit par CHANGEMENT d'état
#: (échec, cause nouvelle, retour à la normale), jamais une par battement (gk2 : disque racine chargé).
_derniere_cause_publication: Dict[str, str] = {}


def _echec_publication(cause: str, message: str) -> bool:
    """Échec BRUYANT : journal en erreur à chaque fois, audit `sade-mode-publication-echec` au premier échec de cette
    cause. Rend False."""
    log.error("sade-mode : publication de %s impossible (%s) : %s", _chemin_fichier_sade(), cause, message)
    if _derniere_cause_publication.get("cause") != cause:
        _derniere_cause_publication["cause"] = cause
        try:
            ecrire_audit(f"sade-mode-publication-echec cause={champ_sain(cause, 64)} "
                         f"fichier={champ_sain(_chemin_fichier_sade(), 128)} operateur=secubox-soc")
        except AuditIndisponible:
            log.error("sade-mode : échec de publication non audité (audit indisponible)")
    return False


def _publication_reussie() -> None:
    if _derniere_cause_publication.pop("cause", None) is not None:
        try:
            ecrire_audit(f"sade-mode-publication-retablie fichier={champ_sain(_chemin_fichier_sade(), 128)} "
                         f"operateur=secubox-soc")
        except AuditIndisponible:
            log.error("sade-mode : retour de la publication non audité (audit indisponible)")


def publier_mode() -> bool:
    """Réécrit le fichier du mode SADE ; True s'il est publié, False sinon (sans lever, mais bruyamment)."""
    try:
        with closing(_connecter()) as db:
            r = db.execute("SELECT valeur FROM mode WHERE id = 1").fetchone()
            cidrs = [c for (c,) in db.execute("SELECT cidr FROM liste_blanche ORDER BY rowid")]
    except (sqlite3.Error, OSError) as e:
        return _echec_publication("base_illisible", f"rien publié ({e.__class__.__name__})")
    contenu = json.dumps({"mode": r[0] if r else "observe", "depuis": _ts(), "liste_blanche": cidrs},
                         ensure_ascii=True) + "\n"
    cible = Path(_chemin_fichier_sade())
    temp = None
    try:
        fd, temp = tempfile.mkstemp(prefix=".sade-mode.", suffix=".tmp", dir=str(cible.parent))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o644)  # lu par le compte du WAF : jamais un secret, la liste blanche est publique
            f.write(contenu)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.replace(temp, cible)
        except PermissionError as e:
            # /run/secubox est 1777 (sticky) : la cible appartient à un autre compte, elle ne peut être remplacée
            return _echec_publication("fichier_etranger", f"{cible} appartient à un autre compte : il n'est pas "
                                      f"remplacé, gk2 ne le croit pas ({e.__class__.__name__})")
        temp = None
    except OSError as e:
        return _echec_publication(e.__class__.__name__, "écriture impossible")
    finally:
        if temp is not None:
            try:
                os.unlink(temp)
            except OSError:
                log.error("sade-mode : temporaire %s non retiré", temp)
    _publication_reussie()
    return True


def seuils() -> Dict[str, str]:
    with closing(_connecter()) as db:
        return dict(db.execute("SELECT cle, valeur FROM seuils ORDER BY cle").fetchall())


def liste_blanche() -> List[Dict[str, Any]]:
    with closing(_connecter()) as db:
        return [{"cidr": c, "motif": m, "par": p, "ts": t, "supprimable": not a}
                for c, m, p, t, a in db.execute("SELECT cidr, motif, par, ts, amorcee FROM liste_blanche ORDER BY rowid")]


# ── liste blanche : ajout et retrait audités (#3839) ──────────────────────────────────────────────
# Une adresse en liste blanche n'est jamais bannie par SADE (approbation ni exécuteur automatique). Un réseau trop
# large neutraliserait la défense : au plus /24 en IPv4, /48 en IPv6 (un abonné reçoit un /56 ou un /64 ; un /32 IPv6
# couvrirait un opérateur entier). Les réseaux IPv6 qui portent de l'IPv4 (::ffff:0:0/96, ::/96, 6to4, NAT64) sont
# refusés : ils contourneraient la borne IPv4. Les entrées amorcées
# (privé, boucle, lien-local, CGNAT) restent protégées par les déclencheurs de la base.
LISTE_BLANCHE_MAX = 64
PREFIXE_MIN = {4: 24, 6: 48}
_V6_PORTEURS_V4 = tuple(ipaddress.ip_network(n) for n in ("::ffff:0:0/96", "::/96", "2002::/16", "64:ff9b::/96"))
_MOTIF = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")


def normaliser_cidr(texte: Any, borne: bool = True) -> str:
    """Réseau canonique (`203.0.113.7/32`, `2a01:db8::/64`) ou ValueError (illisible ; trop large si `borne`)."""
    if not isinstance(texte, str) or not texte.strip() or len(texte) > 64:
        raise ValueError("cidr_illisible")
    try:
        n = ipaddress.ip_network(texte.strip(), strict=False)
    except ValueError as e:
        raise ValueError("cidr_illisible") from e
    if borne and n.prefixlen < PREFIXE_MIN[n.version]:
        raise ValueError("cidr_trop_large")
    if borne and n.version == 6 and any(n.overlaps(r) for r in _V6_PORTEURS_V4):
        raise ValueError("cidr_illisible")
    return n.with_prefixlen


def ajouter_liste_blanche(cidr: Any, motif: Any, par: str) -> str:
    """Ajoute un réseau, audit `sade-liste-blanche-ajout` écrit AVANT le COMMIT (rien sans trace). Rend le réseau
    canonique. ValueError : cidr illisible/trop large, motif invalide, déjà présent, liste pleine."""
    net = normaliser_cidr(cidr)
    if (not isinstance(motif, str) or not _MOTIF.match(motif.strip())
            or any(unicodedata.category(c) in ("Cf", "Zl", "Zp") for c in motif)):  # contrôle bidirectionnel, invisibles
        raise ValueError("motif_invalide")
    try:
        db = _connecter()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    with closing(db):
        try:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM liste_blanche WHERE cidr = ?", (net,)).fetchone():
                db.execute("ROLLBACK")
                raise ValueError("deja_presente")
            if db.execute("SELECT COUNT(*) FROM liste_blanche WHERE amorcee = 0").fetchone()[0] >= LISTE_BLANCHE_MAX:
                db.execute("ROLLBACK")
                raise ValueError("liste_pleine")
            db.execute("INSERT INTO liste_blanche(cidr, motif, par, ts, amorcee) VALUES (?,?,?,?,0)",
                       (net, motif.strip(), _operateur_sain(par), _ts()))
            ecrire_audit(f"sade-liste-blanche-ajout cidr={champ_sain(net, 64)} motif={champ_sain(motif.strip(), 80)} "
                         f"operateur={_operateur_sain(par)}")
            db.execute("COMMIT")
        except (AuditIndisponible, ValueError):
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        except sqlite3.Error as e:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise EtatIndisponible(e.__class__.__name__) from e
    publier_mode()
    return net


def retirer_liste_blanche(cidr: Any, par: str) -> str:
    """Retire un réseau ajouté (jamais une entrée amorcée : PermissionError), audit `sade-liste-blanche-retrait`
    AVANT le COMMIT. KeyError s'il n'existe pas."""
    net = normaliser_cidr(cidr, borne=False)  # désigner une entrée système large (10.0.0.0/8) doit dire « système »
    try:
        db = _connecter()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    with closing(db):
        try:
            db.execute("BEGIN IMMEDIATE")
            r = db.execute("SELECT amorcee FROM liste_blanche WHERE cidr = ?", (net,)).fetchone()
            if r is None:
                db.execute("ROLLBACK")
                raise KeyError(net)
            if r[0]:
                db.execute("ROLLBACK")
                raise PermissionError("entree_amorcee")
            db.execute("DELETE FROM liste_blanche WHERE cidr = ? AND amorcee = 0", (net,))
            ecrire_audit(f"sade-liste-blanche-retrait cidr={champ_sain(net, 64)} operateur={_operateur_sain(par)}")
            db.execute("COMMIT")
        except (AuditIndisponible, KeyError, PermissionError):
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        except sqlite3.Error as e:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise EtatIndisponible(e.__class__.__name__) from e
    publier_mode()
    return net

# ── décisions de la file d'approbation (REACTIVE) ────────────────────────────────────────────────
#
# Une décision est identifiée par l'EMPREINTE de la proposition (geste, adresses, durée), pas par l'acteur. Seule la
# dernière génération d'une empreinte compte. Une décision tranchée se ré-arme (nouvelle génération) quand le ban est
# expiré (`tranche_ts + (ttl_s ou 4 h) + 5 min`) ou quand un refus a plus de 24 h ; son état effectif est alors
# `en_attente`. Une ligne `en_cours` ne se débloque que par `reprendre`, après le délai maximal des appels au WAF.

# `approuve` (#3839, 1.12.0) : geste gradué (limiter, leurre, prolonger) approuvé par un administrateur, en file pour
# l'exécuteur `sade-auto` (l'API garde NoNewPrivileges : elle ne lance jamais sudo). `approuve → en_cours` se prend
# dans UNE transaction (`prendre_approuvee`), puis `conclure` ; jamais ré-armable par le temps : une approbation
# non exécutée revient `en_attente` par `abandonner_approuvee` (expirée, cible devenue protégée…).
ETATS_DECISION = ("en_attente", "approuve", "en_cours", "applique", "refuse")
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


def auteurs_decisions() -> Dict[str, str]:
    """{empreinte: opérateur (`par`) de la dernière génération}. Sert à reconnaître une décision de l'exécuteur
    automatique ; l'appelant n'expose jamais le nom d'un opérateur humain."""
    try:
        with closing(_connecter()) as db:
            lignes = db.execute(
                "SELECT d.empreinte, d.par FROM decisions d JOIN "
                "(SELECT empreinte, MAX(generation) g FROM decisions GROUP BY empreinte) m "
                "ON d.empreinte = m.empreinte AND d.generation = m.g").fetchall()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return {e: (par or "") for e, par in lignes}


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
    if etat not in ("en_cours", "refuse", "approuve"):
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


def approuvees() -> List[Dict[str, Any]]:
    """Décisions dont la DERNIÈRE génération est `approuve`, la plus ancienne demande d'abord : la file de sade-auto."""
    try:
        with closing(_connecter()) as db:
            lignes = db.execute(
                f"SELECT d.empreinte, {', '.join('d.' + c for c in _COLS)} FROM decisions d JOIN "
                "(SELECT empreinte, MAX(generation) g FROM decisions GROUP BY empreinte) m "
                "ON d.empreinte = m.empreinte AND d.generation = m.g WHERE d.etat = 'approuve' "
                "ORDER BY d.demande_ts, d.id").fetchall()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return [dict(zip(("empreinte",) + _COLS, x)) for x in lignes]


def _transition_approuvee(empreinte: str, generation: int, demande_ts: str, vers: str, ligne_audit: str,
                          modes: Optional[Tuple[str, ...]], resultat: Optional[str]) -> "Reclamation":
    """`approuve` → `vers` pour (empreinte, génération, demande_ts) exacts, dans UNE transaction BEGIN IMMEDIATE ; audit
    écrit (fsync) AVANT le COMMIT. `modes` : le mode relu doit en faire partie (`ModeRefuse` sinon). Ligne qui n'est
    plus cette approbation : `DejaTraitee` (un second passage ne l'exécute jamais)."""
    try:
        db = _connecter()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    with closing(db):
        try:
            db.execute("BEGIN IMMEDIATE")
            if modes is not None:
                r = db.execute("SELECT valeur FROM mode WHERE id = 1").fetchone()
                if (r[0] if r else "observe") not in modes:
                    db.execute("ROLLBACK")
                    raise ModeRefuse(r[0] if r else "observe")
            maintenant = _ts()
            cur = db.execute("UPDATE decisions SET etat = ?, demande_ts = ?, resultat = ? WHERE empreinte = ? "
                             "AND generation = ? AND etat = 'approuve' AND demande_ts = ?",
                             (vers, maintenant if vers == "en_cours" else demande_ts,
                              None if resultat is None else resultat[:500], empreinte, generation, demande_ts))
            if cur.rowcount != 1:
                db.execute("ROLLBACK")
                raise DejaTraitee("plus approuvée")
            ecrire_audit(f"{ligne_audit} generation={generation}")
            db.execute("COMMIT")
            rec = Reclamation(generation)
            rec.demande_ts = maintenant if vers == "en_cours" else demande_ts
            return rec
        except (AuditIndisponible, ModeRefuse, DejaTraitee):
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        except sqlite3.Error as e:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise EtatIndisponible(e.__class__.__name__) from e


def prendre_approuvee(empreinte: str, generation: int, demande_ts: str, ligne_audit: str,
                      modes: Tuple[str, ...] = ("reactive", "active")) -> "Reclamation":
    """Prend une approbation pour l'exécuter : `approuve → en_cours` (demande_ts = maintenant, pour `reprendre`)."""
    return _transition_approuvee(empreinte, generation, demande_ts, "en_cours", ligne_audit, modes, None)


def abandonner_approuvee(empreinte: str, generation: int, demande_ts: str, resultat: str, ligne_audit: str) -> None:
    """Rend une approbation non exécutée à la file humaine : `approuve → en_attente`, motif dans `resultat`."""
    _transition_approuvee(empreinte, generation, demande_ts, "en_attente", ligne_audit, None, resultat)


def gestes_humains_depuis(geste: str, secondes: int, maintenant: Optional[float] = None) -> int:
    """ADRESSES d'un geste approuvé par un humain (`par` ≠ 'sade-auto') prises pour exécution ou rendues après un essai,
    dont la demande tombe dans les `secondes` dernières secondes : plafond horaire par geste des approbations (jamais
    le journal ai-ban). Compte `en_cours`, `applique` et `en_attente` (un échec a pu poser une partie des adresses ;
    une approbation abandonnée compte aussi : on surcompte plutôt que de sous-compter). Lève `EtatIndisponible`."""
    fin = maintenant if maintenant is not None else datetime.now(timezone.utc).timestamp()
    debut = datetime.fromtimestamp(fin - secondes, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with closing(_connecter()) as db:
            lignes = db.execute("SELECT cible FROM decisions WHERE geste = ? AND COALESCE(par, '') != 'sade-auto' "
                                "AND etat IN ('en_cours', 'applique', 'en_attente') AND demande_ts >= ?",
                                (geste, debut)).fetchall()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return sum(len([a for a in (lg[0] or "").split(",") if a.strip()]) for lg in lignes)


def resultats_decisions() -> Dict[str, str]:
    """{empreinte: résultat de la dernière génération} (issue réelle d'une approbation, pour la page administrateur)."""
    try:
        with closing(_connecter()) as db:
            lignes = db.execute(
                "SELECT d.empreinte, d.resultat FROM decisions d JOIN "
                "(SELECT empreinte, MAX(generation) g FROM decisions GROUP BY empreinte) m "
                "ON d.empreinte = m.empreinte AND d.generation = m.g").fetchall()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return {e: r for e, r in lignes if r}


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
            # COALESCE : un refus sans opérateur enregistré compte comme humain (échec fermé)
            r = db.execute("SELECT 1 FROM decisions WHERE empreinte = ? AND etat = 'refuse' "
                           "AND COALESCE(par, '') != 'sade-auto' LIMIT 1", (empreinte,)).fetchone()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return r is not None


def adresses_refusees_par_humain() -> List[str]:
    """Adresses (texte brut de `cible`, séparées par `,`) de toute décision REFUSÉE par un autre opérateur que
    l'exécuteur automatique, toutes générations et empreintes confondues : une adresse refusée une fois par un humain
    exclut du chemin automatique toute proposition qui la contient (durée ou lot différents). Lève `EtatIndisponible`."""
    try:
        with closing(_connecter()) as db:
            lignes = db.execute("SELECT cible FROM decisions WHERE etat = 'refuse' "
                                "AND COALESCE(par, '') != 'sade-auto'").fetchall()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    return [a.strip() for (c,) in lignes for a in (c or "").split(",") if a.strip()]


RETENTION_VUES_S = 30 * 86400


def noter_propositions_vues(empreintes: List[str]) -> Dict[str, str]:
    """Note la PREMIÈRE vue de chaque empreinte (INSERT OR IGNORE : une vue plus ancienne n'est jamais rajeunie) et rend
    {empreinte: vu_ts} pour celles données. Purge les vues de plus de 30 jours dont l'empreinte n'est plus proposée
    (une proposition encore présente garde sa première vue). Une transaction ; lève `EtatIndisponible`."""
    maintenant = _ts()
    limite = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - RETENTION_VUES_S,
                                    timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        db = _connecter()
    except (sqlite3.Error, OSError) as e:
        raise EtatIndisponible(e.__class__.__name__) from e
    with closing(db):
        try:
            db.execute("BEGIN IMMEDIATE")
            db.executemany("INSERT OR IGNORE INTO propositions_vues(empreinte, vu_ts) VALUES (?, ?)",
                           [(e, maintenant) for e in empreintes])
            courantes = set(empreintes)
            anciennes = [e for (e,) in db.execute("SELECT empreinte FROM propositions_vues WHERE vu_ts < ?", (limite,))
                         if e not in courantes]
            db.executemany("DELETE FROM propositions_vues WHERE empreinte = ?", [(e,) for e in anciennes])
            vues = {e: t for e, t in db.execute("SELECT empreinte, vu_ts FROM propositions_vues")
                    if e in courantes}
            db.execute("COMMIT")
        except sqlite3.Error as e:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise EtatIndisponible(e.__class__.__name__) from e
    return vues


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
