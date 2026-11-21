# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Exécuteur des réponses (#3723, V2 § 10.3) : SEUL chemin d'écriture de gk3 vers gk2, les routes `ai-ban`.

Une passe (boucle `reponses`, 10 s, dans secubox-ai-veille) :

1. relaie dans audit.log les décisions écrites par l'API (lignes `audit_chaine` marquées `relais`) ;
2. sans clé `ai-ban` (absente, valeur de repli « absente » de systemd, illisible) : aucune exécution, état visible
   dans `/veille/etat` ; jamais d'arrêt du processus ;
3. RAPPROCHEMENT d'abord : toute ligne `actions` restée en `envoi` (arrêt en plein envoi, délai, réponse illisible)
   est confrontée à `GET /ai/etat` (cible, geste, fin compatible avec l'heure d'envoi ; un id de gk2 déjà attribué à
   une autre action n'est jamais repris). Trouvée : `faite` ; absente : `echec`. Jamais renvoyée. Tant qu'une ligne
   n'est pas rapprochée (gk2 injoignable), RIEN d'autre n'est envoyé ;
4. propositions retenues : `approuvee` (décision humaine, envoyée en `clic`) ou `proposee` d'office (`mode = auto`,
   politique en mode hybride et geste d'office, automatique NON suspendu), non expirées, sans action ; par gravité du
   dossier, nombre d'étapes, puis récence ; plafonds de gk3 (`politiques.toml`, ≤ ceux de gk2) sur les envois de
   l'heure et du jour. Une proposition expirée (`proposee` ou `approuvee`) passe `expiree` sans envoi ;
5. pour chacune : corps du geste (forme EXACTE des modèles de gk2 ; `prolonger` et `unban` visent l'id de gk2 rendu
   au ban de la proposition `reference`, sinon `echec` local sans envoi) ; la ligne `actions` est créée en `envoi`
   (avec le `jti` et l'empreinte de la clé) et la proposition passe `envoyee` DANS UNE TRANSACTION, AVANT le premier
   octet envoyé ; puis la réponse de gk2 est enregistrée telle quelle : 200 → `faite` (id et fin de gk2) ;
   409/404 → `refusee_gk2` (motif) ; autre statut → `echec` ; réponse perdue → reste `envoi` (rapprochée à la passe
   suivante), la passe s'arrête.

Suspension d'elle-même : trois 409 `plafond_*` en 10 min, ou un 503, posent la suspension de l'automatique dans
veille.db (survit au redémarrage) avec l'audit `veille-auto-suspendue` ; les propositions approuvées restent envoyées.
Seul un administrateur la lève (`POST /veille/reprendre`, `secubox-aictl veille reprendre`).

Audit : chaque envoi, réponse, rapprochement, échec local et suspension → une ligne `audit_chaine` (dans la
transaction) et une ligne de `/var/log/secubox/audit.log` (après validation ; ajout seul ; jamais le jeton ni la clé,
le `jti` et l'empreinte `kid` de la clé seulement). Appels SQLite par `veille.sql` (hors de la boucle), écriture du
journal par `asyncio.to_thread`.
"""
import asyncio
import errno
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from veille import decisions
from veille.client import ErreurGk2
from veille.decisions import ACTEUR_VEILLE, ajouter_audit, iso

log = logging.getLogger("secubox-ai-veille")

AUDIT_LOG = "/var/log/secubox/audit.log"
DEPOT_DEMANDES = "/run/secubox-ai/demandes"
ROUTES = {"ban": "ai_ban", "ban_bloc": "ai_ban", "unban": "ai_unban", "prolonger": "ai_prolonger",
          "limiter": "ai_limiter", "leurre": "ai_leurre", "partager": "ai_partager"}
#: Liste de GET /ai/etat où un geste fait apparaît (rapprochement).
LISTES_ETAT = {"ban": "actifs", "ban_bloc": "actifs", "limiter": "limites", "leurre": "leurres",
               "partager": "partages"}
FENETRE_PLAFONDS_S = 600
SEUIL_PLAFONDS = 3
RAFRAICHIR_RELEVE_S = 60
TOLERANCE_S = 120
DUREE_MIN_S, DUREE_MAX_S = 3600, 7 * 86400
LOT = 20
TAILLE_REPONSE = 4096
DELAI_DEMANDE_ACL_S = 600
_RE_ID = re.compile(r"^[0-9a-f]{32}$")
_RE_CONSEIL = re.compile(r"[^A-Za-z0-9._-]")
_RE_FAMILLE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
FAMILLE_DEFAUT = "riposte"
#: Décisions écrites par l'API (`relais`) → événement d'audit.log.
RELAIS = {"proposition_approuvee": "ai-proposition-approuvee", "proposition_refusee": "ai-proposition-refusee",
          "veille_suspendre": "veille-suspendue", "veille_reprendre": "veille-reprise"}
_ORDRE = ("SELECT p.id, p.version, p.etat, p.geste, p.cible, p.duree_s, p.mode, p.reference, p.motif "
          "FROM propositions p LEFT JOIN dossiers d ON d.id = p.dossier_id "
          "WHERE p.expire_le > ? AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.proposition_id = p.id) "
          "AND (p.etat = 'approuvee' OR (p.etat = 'proposee' AND p.mode = 'auto')) "
          "ORDER BY CASE d.gravite WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
          "ELSE 0 END DESC, CASE WHEN json_valid(d.etapes_json) THEN json_array_length(d.etapes_json) ELSE 0 END DESC, "
          "p.cree_le DESC, p.id LIMIT ?")
_CHAMPS = ("id", "version", "etat", "geste", "cible", "duree_s", "mode", "reference", "motif")
_demande_acl = {"derniere": 0.0}


class _Ecarte(Exception):
    """La proposition ne part pas (état changé, suspendue, plafond de gk3, déjà exécutée) : rien n'est envoyé."""


# ── journal d'audit (ajout seul) ──

def _demander_acl() -> None:
    """audit.log refusé (rotation : nouveau fichier sans l'ACL de la veille) : dépose `acl-audit.demande` pour le
    contrôleur root (`secubox-aictl demandes`), au plus une fois par 10 min. Jamais bloquant."""
    maintenant = time.monotonic()
    if _demande_acl["derniere"] and maintenant - _demande_acl["derniere"] < DELAI_DEMANDE_ACL_S:
        return
    _demande_acl["derniere"] = maintenant
    try:
        fd = os.open(os.path.join(os.environ.get("SECUBOX_AI_DEMANDES", DEPOT_DEMANDES), "acl-audit.demande"),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        os.close(fd)
    except FileExistsError:
        pass
    except OSError as e:
        log.warning("demande d'ACL d'audit non déposée (%s)", e.__class__.__name__)


def ecrire_audit(evenement: str, details: dict) -> bool:
    """Une ligne JSON en ajout seul dans audit.log (jamais un jeton ni une clé) ; rend False si elle n'a pas pu être
    écrite (elle est alors dite au journal du service, jamais perdue en silence). Le fichier n'est jamais créé ici
    (il appartient au compte secubox)."""
    ligne = json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "type": "ai",
                        "evenement": evenement, **details}, ensure_ascii=True, sort_keys=True)
    try:
        fd = os.open(os.environ.get("SECUBOX_AI_AUDIT", AUDIT_LOG),
                     os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.write(fd, (ligne + "\n").encode())
        finally:
            os.close(fd)
        return True
    except OSError as e:
        log.warning("audit.log non écrit (%s) : %s", e.__class__.__name__, ligne)
        if e.errno in (errno.EACCES, errno.EPERM):
            _demander_acl()
        return False


async def _journaliser(journal, lignes) -> None:
    for evenement, details in lignes:
        await asyncio.to_thread(journal, evenement, details)


# ── clé ──

def lire_cle(dossier: Optional[str], nom: str) -> Optional[bytes]:
    """Clé remise par systemd (`$CREDENTIALS_DIRECTORY/<nom>`), ou None : pas de remise, fichier absent, vide ou
    valeur de repli « absente » (SetCredential=). Jamais journalisée."""
    if not dossier:
        return None
    try:
        with open(os.path.join(dossier, nom), "rb") as f:
            cle = f.read(8192)
    except OSError:
        return None
    return None if cle.strip() in (b"", b"absente") else cle


def _poser_si_change(db, cle, valeur, maintenant):
    texte = json.dumps(valeur, sort_keys=True)
    if decisions.lire_etat(db, cle) == texte:
        return
    db.execute("BEGIN IMMEDIATE")
    try:
        decisions.poser_etat(db, cle, texte, maintenant)
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


# ── relais des décisions de l'API ──

async def relayer_audit(veille, journal) -> int:
    """Recopie dans audit.log, dans l'ordre et une seule fois, les lignes `relais` d'audit_chaine (décisions de
    l'API). S'arrête à la première ligne non écrite (reprise à la passe suivante)."""
    def lire(db):
        try:
            depuis = int(decisions.lire_etat(db, "audit_relai") or 0)
        except ValueError:
            depuis = 0
        return depuis, db.execute(
            "SELECT id, horodatage, acteur, operation, objet, resultat, details_json FROM audit_chaine "
            "WHERE id > ? AND json_valid(details_json) AND json_extract(details_json, '$.relais') = 1 "
            "ORDER BY id LIMIT 200", (depuis,)).fetchall()
    depuis, lignes = await veille.sql(lire)
    dernier = depuis
    for ident, h, acteur, operation, objet, resultat, brut in lignes:
        try:
            details = json.loads(brut)
        except ValueError:
            details = {}
        details = {k: v for k, v in details.items() if k != "relais"} if isinstance(details, dict) else {}
        evenement = RELAIS.get(operation, "ai-decision")
        if not await asyncio.to_thread(journal, evenement, {"acteur": acteur, "objet": objet, "resultat": resultat,
                                                            "horodatage": h, **details}):
            break
        dernier = ident
    if dernier != depuis:
        await veille.sql(lambda db: _poser_si_change(db, "audit_relai", dernier, datetime.now(timezone.utc)))
    return dernier - depuis


# ── relevé de /ai/etat ──

def _entier(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _entrees(etat, liste):
    """Entrées valides d'une liste de /ai/etat (données NON FIABLES de gk2)."""
    out = []
    for e in (etat.get(liste) if isinstance(etat, dict) else None) or []:
        if (isinstance(e, dict) and isinstance(e.get("id"), str) and _RE_ID.fullmatch(e["id"])
                and isinstance(e.get("cible"), str) and len(e["cible"]) <= 64 and _entier(e.get("fin"))):
            out.append(e)
    return out


def _releve(etat, maintenant) -> dict:
    sade = etat.get("sade_mode") if isinstance(etat, dict) else None
    plafonds = {}
    for g, p in ((etat.get("plafonds_par_geste") if isinstance(etat, dict) else None) or {}).items():
        if isinstance(g, str) and g in ROUTES and isinstance(p, dict):
            plafonds[g] = {k: p[k] for k in ("heure", "jour", "restant_heure", "restant_jour") if _entier(p.get(k))}
    return {"lu_le": iso(maintenant), "sade_mode": sade if sade in ("observe", "reactive", "active", "aggressive")
            else None, "plafonds_par_geste": plafonds}


async def _lire_etat_gk2(veille, client, maintenant):
    """GET /ai/etat (compte ai-lecture) ; le relevé utile à la console est gardé dans veille.db. None si illisible."""
    try:
        etat = await client.get("ai_etat")
    except ErreurGk2 as e:
        log.warning("exécuteur : /ai/etat illisible (%s %s)", e.code, e.motif)
        return None
    if not isinstance(etat, dict):
        return None
    await veille.sql(lambda db: _poser_si_change(db, "ai_etat", _releve(etat, maintenant), maintenant))
    return etat


def _releve_perime(db, maintenant) -> bool:
    try:
        lu = json.loads(decisions.lire_etat(db, "ai_etat") or "{}").get("lu_le")
    except (ValueError, AttributeError):
        lu = None
    return not lu or lu < iso(maintenant - timedelta(seconds=RAFRAICHIR_RELEVE_S))


# ── rapprochement ──

def _instant(texte) -> float:
    return datetime.fromisoformat(texte.replace("Z", "+00:00")).timestamp()


def _rapprocher_db(db, en_cours, etat, maintenant):
    lignes = []
    h = iso(maintenant)
    db.execute("BEGIN IMMEDIATE")
    try:
        tous = {e["id"] for liste in set(LISTES_ETAT.values()) for e in _entrees(etat, liste)}
        for aid, pid, geste, cible, id_cible, envoyee_le, duree in en_cours:
            envoi = _instant(envoyee_le)
            trouve = None
            if geste in LISTES_ETAT:
                for e in _entrees(etat, LISTES_ETAT[geste]):
                    if (e["cible"] == cible and envoi + DUREE_MIN_S - TOLERANCE_S <= e["fin"]
                            <= envoi + DUREE_MAX_S + TOLERANCE_S
                            and not db.execute("SELECT 1 FROM actions WHERE id_gk2 = ? AND id != ?",
                                               (e["id"], aid)).fetchone()):
                        trouve = e
                        break
            elif geste == "prolonger":
                trouve = next((e for e in _entrees(etat, "actifs") if e["id"] == id_cible
                               and e["fin"] >= envoi + int(duree or 0) - TOLERANCE_S), None)
            elif geste == "unban":
                trouve = {"id": id_cible, "fin": None} if id_cible and id_cible not in tous else None
            if trouve is not None:
                db.execute("UPDATE actions SET etat = 'faite', id_gk2 = ?, fin_gk2 = ?, motif = 'rapprochee', "
                           "rapprochee_le = ? WHERE id = ?", (trouve["id"], trouve["fin"], h, aid))
                db.execute("UPDATE propositions SET etat = 'faite', maj_le = ? WHERE id = ? AND etat = 'envoyee'",
                           (envoyee_le, pid))
                resultat = "faite"
            else:
                db.execute("UPDATE actions SET etat = 'echec', motif = 'absente_apres_envoi', rapprochee_le = ? "
                           "WHERE id = ?", (h, aid))
                db.execute("UPDATE propositions SET etat = 'echec', maj_le = ? WHERE id = ? AND etat = 'envoyee'",
                           (h, pid))
                resultat = "echec"
            details = {"proposition": pid, "action": aid, "geste": geste, "cible": cible, "resultat": resultat,
                       "id_gk2": trouve["id"] if trouve else None}
            ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_rapprochee", pid, resultat, details)
            lignes.append(("ai-reponse-rapprochee", details))
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return lignes


async def rapprocher(veille, client, maintenant, journal=ecrire_audit) -> bool:
    """Rapproche les actions restées en `envoi` ; rend False si l'une d'elles n'a pas pu l'être (rien d'autre ne
    doit partir alors)."""
    en_cours = await veille.sql(lambda db: db.execute(
        "SELECT a.id, a.proposition_id, a.geste, a.cible, a.id_cible_gk2, a.envoyee_le, p.duree_s FROM actions a "
        "JOIN propositions p ON p.id = a.proposition_id WHERE a.etat = 'envoi' ORDER BY a.envoyee_le").fetchall())
    if not en_cours:
        return True
    etat = await _lire_etat_gk2(veille, client, maintenant)
    if etat is None:
        log.warning("exécuteur : %d envoi(s) à rapprocher, gk2 illisible : aucun nouvel envoi", len(en_cours))
        return False
    lignes = await veille.sql(_rapprocher_db, en_cours, etat, maintenant)
    await _journaliser(journal, lignes)
    return True


# ── choix et envoi ──

def _suspendu(db, pol) -> bool:
    return pol.automatique_suspendu or decisions.suspension(db)["suspendu"]


def _auto_permis(db, pol, geste) -> bool:
    return pol.mode == "hybride" and pol.admet(geste) and pol.mode_de(geste) == "auto" and not _suspendu(db, pol)


def _choisir(db, maintenant, pol):
    """Expire ce qui doit l'être, puis rend les propositions à envoyer dans l'ordre (gravité, étapes, récence)."""
    h = iso(maintenant)
    db.execute("BEGIN IMMEDIATE")
    try:
        for pid, etat, geste, cible in db.execute(
                "SELECT id, etat, geste, cible FROM propositions WHERE etat IN ('proposee', 'approuvee') "
                "AND expire_le <= ? AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.proposition_id = propositions.id)",
                (h,)).fetchall():
            db.execute("UPDATE propositions SET etat = 'expiree', maj_le = ? WHERE id = ?", (h, pid))
            if etat == "approuvee":
                ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_expiree", pid, "expiree",
                              {"geste": geste, "cible": cible})
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    retenues = []
    for r in db.execute(_ORDRE, (h, LOT)).fetchall():
        p = dict(zip(_CHAMPS, r))
        if p["geste"] not in ROUTES or not pol.admet(p["geste"]):
            continue
        if p["etat"] == "proposee" and not _auto_permis(db, pol, p["geste"]):
            continue
        retenues.append(p)
    return retenues


def _famille(db, cible) -> str:
    for (f,) in db.execute("SELECT famille FROM evenements WHERE ip_src = ? GROUP BY famille "
                           "ORDER BY COUNT(*) DESC, famille LIMIT 5", (cible,)).fetchall():
        if isinstance(f, str) and _RE_FAMILLE.fullmatch(f):
            return f
    return FAMILLE_DEFAUT


def _construire(db, p):
    """(corps, id visé chez gk2, motif d'échec local). Forme EXACTE des modèles de gk2 (gestes_ia.py)."""
    geste = p["geste"]
    conseil = "v2-" + _RE_CONSEIL.sub("", p["id"])[:61]
    mode = "clic" if p["etat"] == "approuvee" else "auto"
    if geste in ("prolonger", "unban"):
        r = db.execute("SELECT a.id_gk2 FROM propositions r JOIN actions a ON a.proposition_id = r.id "
                       "WHERE r.id = ? AND r.geste IN ('ban', 'ban_bloc') AND r.cible = ? AND a.etat = 'faite'",
                       (p["reference"], p["cible"])).fetchone() if p["reference"] else None
        if r is None or not isinstance(r[0], str) or not _RE_ID.fullmatch(r[0]):
            return None, None, "reference"
        if geste == "unban":
            return {"geste": "unban", "id": r[0]}, r[0], None
    duree = p["duree_s"]
    if not _entier(duree) or duree < 1:
        return None, None, "duree"
    motif = (p["motif"] or "")[:200]
    if geste == "prolonger":
        return {"geste": "prolonger", "id": r[0], "duree_s": duree, "conseil": conseil, "motif": motif}, r[0], None
    if geste in ("ban", "ban_bloc"):
        return {"geste": "ban", "cible": p["cible"], "duree_s": duree, "mode": mode, "conseil": conseil,
                "motif": motif}, None, None
    if geste == "partager":
        return {"geste": "partager", "cible": p["cible"], "duree_s": duree, "conseil": conseil,
                "famille": _famille(db, p["cible"])}, None, None
    return {"geste": geste, "cible": p["cible"], "duree_s": duree, "conseil": conseil, "motif": motif}, None, None


def _plafond_gk3(db, pol, geste, maintenant) -> bool:
    p = pol.plafonds.get(geste)
    if p is None:
        return False
    for champ, recul in (("heure", 3600), ("jour", 86400)):
        n = db.execute("SELECT COUNT(*) FROM actions WHERE geste = ? AND envoyee_le > ? AND etat IN ('envoi', 'faite')",
                       (geste, iso(maintenant - timedelta(seconds=recul)))).fetchone()[0]
        if n >= p[champ]:
            return True
    return False


def _inscrire(db, p, action_id, jti, kid, mode, id_cible, maintenant, pol):
    """Ligne `actions` en `envoi` et proposition `envoyee`, AVANT l'envoi. Lève _Ecarte si elle ne doit pas partir."""
    h = iso(maintenant)
    db.execute("BEGIN IMMEDIATE")
    try:
        r = db.execute("SELECT etat, version, expire_le FROM propositions WHERE id = ?", (p["id"],)).fetchone()
        if r is None or r[0] != p["etat"] or r[1] != p["version"] or r[2] <= h:
            raise _Ecarte("etat")
        if p["etat"] == "proposee" and not _auto_permis(db, pol, p["geste"]):
            raise _Ecarte("suspendu")
        if _plafond_gk3(db, pol, p["geste"], maintenant):
            raise _Ecarte("plafond_gk3")
        try:
            db.execute("INSERT INTO actions(id, proposition_id, geste, cible, mode, id_cible_gk2, etat, jti, cle, "
                       "envoyee_le) VALUES (?, ?, ?, ?, ?, ?, 'envoi', ?, ?, ?)",
                       (action_id, p["id"], p["geste"], p["cible"], mode, id_cible, jti, kid, h))
        except sqlite3.IntegrityError:
            raise _Ecarte("deja_executee") from None
        if db.execute("UPDATE propositions SET etat = 'envoyee', maj_le = ? WHERE id = ? AND etat = ?",
                      (h, p["id"], p["etat"])).rowcount != 1:
            raise _Ecarte("etat")
        details = {"proposition": p["id"], "action": action_id, "geste": p["geste"], "cible": p["cible"],
                   "mode": mode, "jti": jti, "cle": kid}
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_envoi", p["id"], "envoi", details)
        db.execute("COMMIT")
        return details
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def _echouer_local(db, p, motif, maintenant):
    h = iso(maintenant)
    db.execute("BEGIN IMMEDIATE")
    try:
        if db.execute("UPDATE propositions SET etat = 'echec', maj_le = ? WHERE id = ? AND etat = ?",
                      (h, p["id"], p["etat"])).rowcount != 1:
            db.execute("ROLLBACK")
            return None
        details = {"proposition": p["id"], "geste": p["geste"], "cible": p["cible"], "motif": motif}
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_echec", p["id"], "echec", details)
        db.execute("COMMIT")
        return details
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def _json_borne(reponse) -> Optional[str]:
    if reponse is None:
        return None
    texte = json.dumps(reponse, ensure_ascii=True, sort_keys=True)
    return texte if len(texte) <= TAILLE_REPONSE else json.dumps({"tronque": True, "octets": len(texte)})


def _enregistrer(db, p, action_id, code, motif, reponse, maintenant):
    """Réponse de gk2 telle quelle ; suspension d'elle-même (3 × 409 plafond_* en 10 min, ou 503)."""
    h = iso(maintenant)
    lignes = []
    db.execute("BEGIN IMMEDIATE")
    try:
        id_gk2 = fin = None
        if code == 200:
            etat = "faite"
            if isinstance(reponse.get("id"), str) and _RE_ID.fullmatch(reponse["id"]):
                id_gk2 = reponse["id"]
            if _entier(reponse.get("fin")):
                fin = reponse["fin"]
            motif = reponse.get("etat") if p["geste"] == "unban" and isinstance(reponse.get("etat"), str) \
                and re.fullmatch(r"[a-z_]{1,32}", reponse["etat"]) else None
        elif code in (404, 409):
            etat = "refusee_gk2"
        else:
            etat = "echec"
        db.execute("UPDATE actions SET etat = ?, code_http = ?, motif = ?, reponse_json = ?, id_gk2 = ?, fin_gk2 = ?, "
                   "repondue_le = ? WHERE id = ?", (etat, code, motif, _json_borne(reponse), id_gk2, fin, h,
                                                    action_id))
        db.execute("UPDATE propositions SET etat = ?, maj_le = ? WHERE id = ? AND etat = 'envoyee'",
                   (etat, h, p["id"]))
        details = {"proposition": p["id"], "action": action_id, "geste": p["geste"], "cible": p["cible"],
                   "code": code, "motif": motif, "id_gk2": id_gk2, "resultat": etat}
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_gk2", p["id"], etat, details)
        lignes.append(("ai-reponse-gk2", details))
        cause = None
        if code == 503:
            cause = "503"
        elif code == 409 and isinstance(motif, str) and motif.startswith("plafond_"):
            n = db.execute("SELECT COUNT(*) FROM actions WHERE code_http = 409 AND motif LIKE 'plafond\\_%' ESCAPE '\\' "
                           "AND repondue_le > ?", (iso(maintenant - timedelta(seconds=FENETRE_PLAFONDS_S)),)
                           ).fetchone()[0]
            if n >= SEUIL_PLAFONDS:
                cause = "plafond"
        if cause and decisions.suspendre_dans(db, ACTEUR_VEILLE, maintenant, cause):
            lignes.append(("veille-auto-suspendue", {"motif": cause, "action": action_id, "code": code,
                                                     "motif_gk2": motif}))
            log.error("exécuteur : automatique suspendu de lui-même (%s) ; les gestes approuvés restent possibles",
                      cause)
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return lignes


def _ambigu(db, p, action_id, motif, maintenant):
    details = {"proposition": p["id"], "action": action_id, "geste": p["geste"], "cible": p["cible"],
               "motif": motif}
    db.execute("BEGIN IMMEDIATE")
    try:
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_perdue", p["id"], "envoi", details)
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return details


async def _executer_une(veille, client, p, maintenant, pol, journal) -> str:
    """« suite » (proposition traitée ou écartée) ou « arret » (issue inconnue, clé illisible : fin de passe)."""
    corps, id_cible, erreur = await veille.sql(_construire, p)
    if erreur:
        details = await veille.sql(_echouer_local, p, erreur, maintenant)
        if details:
            log.warning("exécuteur : %s %s non envoyé (%s)", p["geste"], p["id"], erreur)
            await _journaliser(journal, [("ai-reponse-echec", details)])
        return "suite"
    action_id = str(uuid.uuid4())
    mode = "clic" if p["etat"] == "approuvee" else "auto"

    async def avant_envoi(jti, kid):
        details = await veille.sql(_inscrire, p, action_id, jti, kid, mode, id_cible, maintenant, pol)
        await _journaliser(journal, [("ai-reponse-envoi", details)])

    try:
        reponse = await client.post(ROUTES[p["geste"]], corps, avant_envoi=avant_envoi)
    except _Ecarte as e:
        log.info("exécuteur : %s %s écartée (%s)", p["geste"], p["id"], e)
        return "suite"
    except ValueError as e:
        log.error("exécuteur : clé ai-ban inutilisable (%s) : aucun envoi", e.__class__.__name__)
        await veille.sql(lambda db: _poser_si_change(db, "cle_ai_ban", {"etat": "invalide"}, maintenant))
        return "arret"
    except ErreurGk2 as e:
        if e.code is None:
            details = await veille.sql(_ambigu, p, action_id, e.motif, maintenant)
            log.warning("exécuteur : réponse de gk2 perdue (%s) pour %s : rapprochement à la passe suivante",
                        e.motif, p["id"])
            await _journaliser(journal, [("ai-reponse-perdue", details)])
            return "arret"
        lignes = await veille.sql(_enregistrer, p, action_id, e.code, e.motif, e.reponse, maintenant)
        await _journaliser(journal, lignes)
        return "suite"
    lignes = await veille.sql(_enregistrer, p, action_id, 200, None, reponse, maintenant)
    await _journaliser(journal, lignes)
    return "suite"


async def executer(veille, client, maintenant: datetime, politiques=None,
                   journal: Optional[Callable[[str, dict], bool]] = None) -> None:
    """Une passe de l'exécuteur (cf. docstring du module)."""
    if maintenant.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    journal = journal or ecrire_audit
    await relayer_audit(veille, journal)
    if client is None or not client.peut_agir:
        await veille.sql(lambda db: _poser_si_change(db, "cle_ai_ban", {"etat": "absente"}, maintenant))
        return
    empreinte = await asyncio.to_thread(lambda: client.empreinte_ban)
    if empreinte is None:
        await veille.sql(lambda db: _poser_si_change(db, "cle_ai_ban", {"etat": "invalide"}, maintenant))
        return
    await veille.sql(lambda db: _poser_si_change(db, "cle_ai_ban", {"etat": "presente", "empreinte": empreinte},
                                                 maintenant))
    if not await rapprocher(veille, client, maintenant, journal):
        return
    if await veille.sql(_releve_perime, maintenant):
        await _lire_etat_gk2(veille, client, maintenant)
    if politiques is None:
        from veille.politiques import charger_politiques
        politiques = await asyncio.to_thread(charger_politiques)
    vue = {"mode": politiques.mode, "automatique_suspendu": politiques.automatique_suspendu,
           "plafonds": {g: dict(p) for g, p in politiques.plafonds.items()}}
    await veille.sql(lambda db: _poser_si_change(db, "politique", vue, maintenant))
    for p in await veille.sql(_choisir, maintenant, politiques):
        if await _executer_une(veille, client, p, maintenant, politiques, journal) == "arret":
            break
