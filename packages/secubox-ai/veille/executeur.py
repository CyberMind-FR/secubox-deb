# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Exécuteur des réponses (#3723, V2 § 10.3) : SEUL chemin d'écriture de gk3 vers gk2, les routes `ai-ban`.

Une passe (boucle `reponses`, 10 s, dans secubox-ai-veille) :

1. relaie dans audit.log les décisions écrites par l'API (lignes `audit_chaine` marquées `relais`) ;
2. sans clé `ai-ban` (absente, valeur de repli « absente » de systemd, illisible) : aucune exécution, état visible
   dans `/veille/etat` ; jamais d'arrêt du processus ;
3. RAPPROCHEMENT d'abord : toute ligne `actions` restée en `envoi` depuis plus de `DELAI_RAPPROCHEMENT_S` (arrêt
   en plein envoi, délai, réponse illisible, 5xx autre que 503) est confrontée à `GET /ai/etat` (cible, geste, fin
   compatible avec l'heure d'envoi ; un id de gk2 déjà attribué à une autre action n'est jamais repris). Trouvée :
   `faite` ; absente : `echec` ; levée d'un ban déjà échu : `echec` `echue` (gk2 n'a rien levé). Jamais renvoyée.
   Tant qu'une ligne reste en `envoi` (trop récente, ou gk2 illisible), RIEN d'autre n'est envoyé ;
4. politique en mode `observation` : RIEN ne part, pas même une proposition approuvée (V2 § 10.2). En `hybride` :
   `approuvee` (décision humaine, envoyée en `clic`) ou `proposee` d'office (`mode = auto`, geste d'office,
   automatique NON suspendu — filtré en SQL : une file d'office suspendue n'affame jamais un clic approuvé), non
   expirées, sans action ; par gravité du dossier, nombre d'étapes, puis récence ; plafonds de gk3 (`politiques.toml`,
   ≤ ceux de gk2, `unban` compris) sur les envois de l'heure et du jour. Une proposition expirée (`proposee` ou
   `approuvee`) passe `expiree` sans envoi (une approuvée expirée est auditée). Mode SADE de gk2 (dernier relevé de
   /ai/etat, revue finale I2) : en `observe` aucun geste posé ne part, clic compris ; en `reactive`, d'office
   `limiter` seul ; écartée, la proposition reste telle quelle ;
5. pour chacune : REVALIDATION avant signature (geste du catalogue, cible de la forme du geste, publique et hors des
   plages protégées `[veille.analyste] protegees`, durée dans les bornes de gk2) ; corps aux formes EXACTES des
   modèles de gk2 ; `prolonger` et `unban` visent l'id de gk2 rendu au geste de la proposition `reference` (la levée
   d'une limite ou d'un leurre part vers `POST /ai/lever`, celle d'un ban ou d'un partage vers `/ai/unban`). Tout écart :
   `echec` local audité, rien n'est signé. La ligne `actions` est créée en `envoi` (avec le `jti` et l'empreinte de la
   clé) et la proposition passe `envoyee` DANS UNE TRANSACTION, AVANT le premier octet envoyé ; puis la réponse de gk2
   est enregistrée telle quelle : 200 → `faite` (id et fin de gk2 ; levée `echu` → `refusee_gk2`) ; 409/404 →
   `refusee_gk2` (motif), sauf un 409 non définitif (`REFUS_NON_DEFINITIFS`) : la proposition revient à son état
   sans action, nouvel essai après `REESSAI_S` ; 503, 401, 403 → `echec` et FIN DE PASSE (le reste du lot n'est pas
   brûlé) ; autre 4xx →
   `echec` ; 5xx autre que 503, ou réponse perdue → issue INCONNUE : reste `envoi` (rapprochée plus tard), fin de passe.

Suspension d'elle-même : trois 409 `plafond_*` en 10 min, un 503, ou un 401/403 (clé refusée par gk2, dit par
`/veille/etat`) posent la suspension de l'automatique dans veille.db (survit au redémarrage) avec l'audit
`veille-auto-suspendue` ; les propositions approuvées restent envoyées. Seul un administrateur la lève
(`POST /veille/reprendre`, `secubox-aictl veille reprendre`).

Audit : chaque envoi, réponse, rapprochement, échec local et suspension → une ligne `audit_chaine` (dans la
transaction) et une ligne de `/var/log/secubox/audit.log` (après validation ; ajout seul ; jamais le jeton ni la clé,
le `jti` et l'empreinte `kid` de la clé seulement). Appels SQLite par `veille.sql` (hors de la boucle), écriture du
journal par `asyncio.to_thread`.
"""
import asyncio
import errno
import ipaddress
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
from veille.riposte import _protegee, prefixes_locaux

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
#: Une action en `envoi` plus récente que ceci peut encore recevoir sa réponse (délai du client : 45 s).
DELAI_RAPPROCHEMENT_S = 90
DUREE_MIN_S, DUREE_MAX_S = 3600, 7 * 86400
LOT = 20
TAILLE_REPONSE = 4096
DELAI_DEMANDE_ACL_S = 600
#: Revue finale I2 : refus de gk2 NON définitifs (mode SADE du moment, cibles protégées momentanément inconnues). La
#: proposition revient à son état (proposée ou approuvée) sans action ni plafond consommé ; elle ne repart pas avant
#: `REESSAI_S` (jamais en boucle) et expire comme les autres.
REFUS_NON_DEFINITIFS = frozenset({"sade_observe", "sade_reactive", "protegee_inconnue"})
REESSAI_S = 900
#: Gestes posés soumis au mode SADE de gk2 (`porte_sade`) ; les levées (`unban`) ne le sont pas.
GESTES_SADE = frozenset({"ban", "ban_bloc", "prolonger", "limiter", "leurre", "partager"})
_RE_ID = re.compile(r"^[0-9a-f]{32}$")
_RE_CONSEIL = re.compile(r"[^A-Za-z0-9._-]")
_RE_FAMILLE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
FAMILLE_DEFAUT = "riposte"
#: Bornes de durée de gk2 par geste (gestes_ia.py), revérifiées avant de signer ; bloc d'office : 24 h au plus.
BORNES_DUREE = {"ban": (3600, 7 * 86400), "ban_bloc": (3600, 7 * 86400), "prolonger": (3600, 7 * 86400),
                "limiter": (3600, 86400), "leurre": (3600, 7 * 86400), "partager": (3600, 7 * 86400)}
DUREE_BLOC_AUTO_MAX_S = 86400
#: Décisions écrites par l'API (`relais`) → événement d'audit.log.
RELAIS = {"proposition_approuvee": "ai-proposition-approuvee", "proposition_refusee": "ai-proposition-refusee",
          "veille_suspendre": "veille-suspendue", "veille_reprendre": "veille-reprise",
          "filtre_confirme": "ai-filtre-confirme", "dossier_redescendre": "ai-dossier-redescendre",
          "dossier_analyser": "ai-dossier-analyser", "action_defaire": "ai-action-defaire"}
#: Levée (`unban`) d'un geste sans ban : `POST /ai/lever` de gk2 (#3724), `cible_geste` = le geste visé.
LEVEES_SANS_BAN = ("limiter", "leurre")
# {auto} : « ? » des gestes d'office permis à cette passe (NULL : aucun).
_ORDRE = ("SELECT p.id, p.version, p.etat, p.geste, p.cible, p.duree_s, p.mode, p.reference, p.motif "
          "FROM propositions p LEFT JOIN dossiers d ON d.id = p.dossier_id "
          "WHERE p.expire_le > ? AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.proposition_id = p.id) "
          "AND (p.reessai_le IS NULL OR p.reessai_le <= ?) "
          "AND (p.etat = 'approuvee' OR (p.etat = 'proposee' AND p.mode = 'auto' AND p.geste IN ({auto}))) "
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


#: Fin d'un geste V2 après ses prolongations faites : partagée avec la console (decisions.fin_geste, #3724).
_fin_ban = decisions.fin_geste


def _rapprocher_db(db, en_cours, etat, maintenant):
    lignes = []
    h = iso(maintenant)
    db.execute("BEGIN IMMEDIATE")
    try:
        tous = {e["id"] for liste in set(LISTES_ETAT.values()) for e in _entrees(etat, liste)}
        for aid, pid, geste, cible, id_cible, envoyee_le, duree, reference in en_cours:
            envoi = _instant(envoyee_le)
            trouve = None
            motif = "absente_apres_envoi"
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
            elif geste == "unban" and id_cible and id_cible not in tous:
                fin_ban = _fin_ban(db, reference)
                if fin_ban is not None and fin_ban <= maintenant.timestamp():
                    motif = "echue"          # échu de lui-même : gk2 n'a rien levé, le ban reste compté en récidive
                else:
                    trouve = {"id": id_cible, "fin": None}
            if trouve is not None:
                db.execute("UPDATE actions SET etat = 'faite', id_gk2 = ?, fin_gk2 = ?, motif = 'rapprochee', "
                           "rapprochee_le = ? WHERE id = ?", (trouve["id"], trouve["fin"], h, aid))
                db.execute("UPDATE propositions SET etat = 'faite', maj_le = ? WHERE id = ? AND etat = 'envoyee'",
                           (envoyee_le, pid))
                resultat = "faite"
            else:
                db.execute("UPDATE actions SET etat = 'echec', motif = ?, rapprochee_le = ? WHERE id = ?",
                           (motif, h, aid))
                db.execute("UPDATE propositions SET etat = 'echec', maj_le = ? WHERE id = ? AND etat = 'envoyee'",
                           (h, pid))
                resultat = "echec"
            details = {"proposition": pid, "action": aid, "geste": geste, "cible": cible, "resultat": resultat,
                       "motif": None if trouve else motif, "id_gk2": trouve["id"] if trouve else None}
            ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_rapprochee", pid, resultat, details)
            lignes.append(("ai-reponse-rapprochee", details))
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return lignes


async def rapprocher(veille, client, maintenant, journal=ecrire_audit) -> bool:
    """Rapproche les actions restées en `envoi` depuis plus de DELAI_RAPPROCHEMENT_S ; rend False s'il en reste une
    (trop récente, ou gk2 illisible) : rien d'autre ne doit partir alors."""
    en_cours = await veille.sql(lambda db: db.execute(
        "SELECT a.id, a.proposition_id, a.geste, a.cible, a.id_cible_gk2, a.envoyee_le, p.duree_s, p.reference "
        "FROM actions a JOIN propositions p ON p.id = a.proposition_id WHERE a.etat = 'envoi' "
        "ORDER BY a.envoyee_le").fetchall())
    if not en_cours:
        return True
    limite = iso(maintenant - timedelta(seconds=DELAI_RAPPROCHEMENT_S))
    murs = [r for r in en_cours if r[5] <= limite]
    if not murs:
        log.info("exécuteur : %d envoi(s) récent(s) en attente de rapprochement", len(en_cours))
        return False
    etat = await _lire_etat_gk2(veille, client, maintenant)
    if etat is None:
        log.warning("exécuteur : %d envoi(s) à rapprocher, gk2 illisible : aucun nouvel envoi", len(murs))
        return False
    lignes = await veille.sql(_rapprocher_db, murs, etat, maintenant)
    await _journaliser(journal, lignes)
    return len(murs) == len(en_cours)


# ── choix et envoi ──

def _suspendu(db, pol) -> bool:
    return pol.automatique_suspendu or decisions.suspension(db)["suspendu"]


def _gestes_auto(db, pol) -> list:
    """Gestes d'office permis à cette passe : aucun hors du mode hybride ou si l'automatique est suspendu."""
    if pol.mode != "hybride" or _suspendu(db, pol):
        return []
    return [g for g in ROUTES if pol.admet(g) and pol.mode_de(g) == "auto"]


def _choisir(db, maintenant, pol):
    """Expire ce qui doit l'être, puis rend les propositions à envoyer dans l'ordre (gravité, étapes, récence), et les
    lignes d'audit des approuvées expirées. Mode `observation` : rien (pas même un clic approuvé)."""
    h = iso(maintenant)
    lignes = []
    db.execute("BEGIN IMMEDIATE")
    try:
        for pid, etat, geste, cible in db.execute(
                "SELECT id, etat, geste, cible FROM propositions WHERE etat IN ('proposee', 'approuvee') "
                "AND expire_le <= ? AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.proposition_id = propositions.id)",
                (h,)).fetchall():
            db.execute("UPDATE propositions SET etat = 'expiree', maj_le = ? WHERE id = ?", (h, pid))
            if etat == "approuvee":
                details = {"proposition": pid, "geste": geste, "cible": cible}
                ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_expiree", pid, "expiree", details)
                lignes.append(("ai-reponse-expiree", details))
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    if pol.mode != "hybride":
        return [], lignes
    auto = _gestes_auto(db, pol)
    sql = _ORDRE.format(auto=", ".join("?" * len(auto)) or "NULL")
    sade = _sade_releve(db)
    retenues = [p for p in (dict(zip(_CHAMPS, r)) for r in db.execute(sql, (h, h, *auto, LOT)).fetchall())
                if p["geste"] in ROUTES and pol.admet(p["geste"]) and _admis_par_sade(p, sade)]
    return retenues, lignes


def _sade_releve(db) -> Optional[str]:
    """Mode SADE de gk2 au dernier relevé de /ai/etat (None : inconnu, ou aucune porte sur gk2)."""
    try:
        mode = json.loads(decisions.lire_etat(db, "ai_etat") or "{}").get("sade_mode")
    except (ValueError, AttributeError):
        return None
    return mode if mode in ("observe", "reactive", "active", "aggressive") else None


def _admis_par_sade(p, sade) -> bool:
    """Revue finale I2 (miroir de `porte_sade` de gk2) : en `observe`, aucun geste posé ne part, clic compris ; en
    `reactive`, les clics partent, d'office `limiter` seul. Écartée ici, la proposition reste telle quelle : rien
    n'est consommé, elle repartira quand le mode le permettra (ou expirera)."""
    if p["geste"] not in GESTES_SADE or sade not in ("observe", "reactive"):
        return True
    if sade == "observe":
        return False
    return p["etat"] == "approuvee" or p["geste"] == "limiter"


def _famille(db, cible) -> str:
    for (f,) in db.execute("SELECT famille FROM evenements WHERE ip_src = ? GROUP BY famille "
                           "ORDER BY COUNT(*) DESC, famille LIMIT 5", (cible,)).fetchall():
        if isinstance(f, str) and _RE_FAMILLE.fullmatch(f):
            return f
    return FAMILLE_DEFAUT


def _cible_valide(geste, cible, protegees):
    """Motif d'échec, ou None : forme exacte du geste (adresse IPv4 pour `ban`, /24 IPv4 exact pour `ban_bloc`,
    adresse IPv4 ou IPv6 pour limiter/leurre/partager, adresse ou /24 pour prolonger/unban), publique et hors des
    plages protégées (même règle que la riposte et l'analyste)."""
    if not isinstance(cible, str) or len(cible) > 64:
        return "cible"
    try:
        n = ipaddress.ip_network(cible, strict=True)
    except ValueError:
        return "cible"
    if n.with_prefixlen.split("/")[0] != cible.split("/")[0] or ("/" in cible) != (n.prefixlen < n.max_prefixlen):
        return "cible"                       # forme non canonique (zéros, « /32 ») : gk2 la refuserait
    adresse = n.prefixlen == n.max_prefixlen
    bloc = n.version == 4 and n.prefixlen == 24
    formes = {"ban": n.version == 4 and adresse, "ban_bloc": bloc, "prolonger": n.version == 4 and (adresse or bloc),
              "unban": adresse or bloc, "limiter": adresse, "leurre": adresse, "partager": adresse}
    if not formes.get(geste, False):
        return "cible"
    if _protegee(n, protegees):
        return "protegee"
    return None


def _construire(db, p, protegees=()):
    """(corps, id visé chez gk2, motif d'échec local). REVALIDE la ligne avant toute signature (geste du catalogue,
    cible, durée) : une ligne de `propositions` forgée ou corrompue n'est jamais signée. Forme EXACTE des modèles de
    gk2 (gestes_ia.py)."""
    geste = p["geste"]
    if geste not in ROUTES:
        return None, None, "geste"
    motif_cible = _cible_valide(geste, p["cible"], protegees)
    if motif_cible:
        return None, None, motif_cible
    conseil = "v2-" + _RE_CONSEIL.sub("", p["id"])[:61]
    mode = "clic" if p["etat"] == "approuvee" else "auto"
    if geste in ("prolonger", "unban"):
        # prolonger : un ban V2 fait ; unban : un ban, une limite, un leurre ou un partage V2 faits (#3724), de MÊME
        # cible : la levée ne vise jamais que l'id rendu par gk2 au geste de la proposition `reference`.
        visees = ("('ban', 'ban_bloc')" if geste == "prolonger"
                  else "('ban', 'ban_bloc', 'limiter', 'leurre', 'partager')")
        r = db.execute("SELECT a.id_gk2, r.geste FROM propositions r JOIN actions a ON a.proposition_id = r.id "
                       f"WHERE r.id = ? AND r.geste IN {visees} AND r.cible = ? AND a.etat = 'faite'",
                       (p["reference"], p["cible"])).fetchone() if p["reference"] else None
        if r is None or not isinstance(r[0], str) or not _RE_ID.fullmatch(r[0]):
            return None, None, "reference"
        if geste == "unban":
            if r[1] in LEVEES_SANS_BAN:
                return {"geste": "lever", "cible_geste": r[1], "id": r[0]}, r[0], None
            return {"geste": "unban", "id": r[0]}, r[0], None
    duree = p["duree_s"]
    bas, haut = BORNES_DUREE[geste]
    if geste == "ban_bloc" and mode == "auto":
        haut = DUREE_BLOC_AUTO_MAX_S
    if not _entier(duree) or not bas <= duree <= haut:
        return None, None, "duree"
    motif = (p["motif"] or "")[:200]
    if geste == "prolonger":
        return {"geste": "prolonger", "id": r[0], "duree_s": duree, "mode": mode, "conseil": conseil,
                "motif": motif}, r[0], None
    if geste in ("ban", "ban_bloc"):
        return {"geste": "ban", "cible": p["cible"], "duree_s": duree, "mode": mode, "conseil": conseil,
                "motif": motif}, None, None
    if geste == "partager":
        return {"geste": "partager", "cible": p["cible"], "duree_s": duree, "mode": mode, "conseil": conseil,
                "famille": _famille(db, p["cible"])}, None, None
    return {"geste": geste, "cible": p["cible"], "duree_s": duree, "mode": mode, "conseil": conseil,
            "motif": motif}, None, None


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
        if pol.mode != "hybride":
            raise _Ecarte("observation")
        r = db.execute("SELECT etat, version, expire_le FROM propositions WHERE id = ?", (p["id"],)).fetchone()
        if r is None or r[0] != p["etat"] or r[1] != p["version"] or r[2] <= h:
            raise _Ecarte("etat")
        if p["etat"] == "proposee" and p["geste"] not in _gestes_auto(db, pol):
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
        details = {"proposition": p["id"], "geste": p["geste"], "cible": str(p["cible"])[:64], "motif": motif}
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
    """Réponse de gk2 telle quelle ; suspension d'elle-même (3 × 409 plafond_* en 10 min, 503, 401/403)."""
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
            if motif == "echu":
                etat = "refusee_gk2"         # rien n'a été levé : le ban échu reste compté en récidive (comme gk2)
            db.execute("DELETE FROM executeur_etat WHERE cle = 'cle_refusee'")
        elif code == 409 and motif in REFUS_NON_DEFINITIFS:
            etat = "reessai"
        elif code in (404, 409):
            etat = "refusee_gk2"
        else:
            etat = "echec"
        if etat == "reessai":
            # I2 : ni action (UNIQUE(proposition_id) permettra le nouvel envoi), ni plafond consommé ; la trace reste
            # dans audit_chaine et audit.log (ligne ci-dessous)
            db.execute("DELETE FROM actions WHERE id = ?", (action_id,))
            db.execute("UPDATE propositions SET etat = ?, reessai_le = ?, maj_le = ? WHERE id = ? AND etat = 'envoyee'",
                       (p["etat"], iso(maintenant + timedelta(seconds=REESSAI_S)), h, p["id"]))
        else:
            db.execute("UPDATE actions SET etat = ?, code_http = ?, motif = ?, reponse_json = ?, id_gk2 = ?, "
                       "fin_gk2 = ?, repondue_le = ? WHERE id = ?", (etat, code, motif, _json_borne(reponse), id_gk2,
                                                                     fin, h, action_id))
            db.execute("UPDATE propositions SET etat = ?, maj_le = ? WHERE id = ? AND etat = 'envoyee'",
                       (etat, h, p["id"]))
        details = {"proposition": p["id"], "action": action_id, "geste": p["geste"], "cible": p["cible"],
                   "code": code, "motif": motif, "id_gk2": id_gk2, "resultat": etat}
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_gk2", p["id"], etat, details)
        lignes.append(("ai-reponse-gk2", details))
        cause = None
        if code == 503:
            cause = "503"
        elif code in (401, 403):
            cause = "cle_refusee"
            decisions.poser_etat(db, "cle_refusee", json.dumps({"code": code, "motif": motif, "le": h},
                                                               sort_keys=True), maintenant)
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


def _ambigu(db, p, action_id, code, motif, maintenant):
    """Issue inconnue (réponse perdue, 5xx autre que 503) : l'action RESTE en `envoi`, rapprochée plus tard."""
    details = {"proposition": p["id"], "action": action_id, "geste": p["geste"], "cible": p["cible"],
               "code": code, "motif": motif}
    db.execute("BEGIN IMMEDIATE")
    try:
        if code is not None:
            db.execute("UPDATE actions SET code_http = ?, motif = ?, repondue_le = ? WHERE id = ? AND etat = 'envoi'",
                       (code, motif, iso(maintenant), action_id))
        ajouter_audit(db, maintenant, ACTEUR_VEILLE, "reponse_perdue", p["id"], "envoi", details)
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return details


#: Statuts qui arrêtent la passe : le reste du lot n'est pas brûlé contre une panne ou une clé refusée.
_ARRET = frozenset({401, 403, 503})


async def _executer_une(veille, client, p, maintenant, pol, journal, protegees=()) -> str:
    """« suite » (proposition traitée ou écartée) ou « arret » (issue inconnue, panne de gk2, clé refusée ou
    illisible : fin de passe)."""
    corps, id_cible, erreur = await veille.sql(_construire, p, protegees)
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
        route = "ai_lever" if corps.get("geste") == "lever" else ROUTES[p["geste"]]
        reponse = await client.post(route, corps, avant_envoi=avant_envoi)
    except _Ecarte as e:
        log.info("exécuteur : %s %s écartée (%s)", p["geste"], p["id"], e)
        return "suite"
    except ValueError as e:
        log.error("exécuteur : clé ai-ban inutilisable (%s) : aucun envoi", e.__class__.__name__)
        await veille.sql(lambda db: _poser_si_change(db, "cle_ai_ban", {"etat": "invalide"}, maintenant))
        return "arret"
    except ErreurGk2 as e:
        if e.code is None or (e.code >= 500 and e.code != 503):
            details = await veille.sql(_ambigu, p, action_id, e.code, e.motif, maintenant)
            log.warning("exécuteur : issue inconnue (%s %s) pour %s : rapprochement plus tard", e.code, e.motif,
                        p["id"])
            await _journaliser(journal, [("ai-reponse-perdue", details)])
            return "arret"
        lignes = await veille.sql(_enregistrer, p, action_id, e.code, e.motif, e.reponse, maintenant)
        await _journaliser(journal, lignes)
        return "arret" if e.code in _ARRET else "suite"
    lignes = await veille.sql(_enregistrer, p, action_id, 200, None, reponse, maintenant)
    await _journaliser(journal, lignes)
    return "suite"


async def executer(veille, client, maintenant: datetime, politiques=None,
                   journal: Optional[Callable[[str, dict], bool]] = None, protegees=()) -> None:
    """Une passe de l'exécuteur (cf. docstring du module). `protegees` : plages jamais visées
    (`[veille.analyste] protegees` d'ai.toml), revérifiées avant chaque signature."""
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
    # M6 : sans clé ai-lecture, /ai/etat (rapprochement, mode SADE) est lu avec la clé ai-ban ; dit dans /veille/etat
    lecture = {"etat": "presente"} if client.peut_lire else {"etat": "absente", "rapprochement": "ai-ban"}
    await veille.sql(lambda db: _poser_si_change(db, "cle_ai_lecture", lecture, maintenant))
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
    retenues, lignes = await veille.sql(_choisir, maintenant, politiques)
    await _journaliser(journal, lignes)
    protegees = list(protegees) + await asyncio.to_thread(prefixes_locaux)     # I3 : LAN connu de gk3
    for p in retenues:
        if await _executer_une(veille, client, p, maintenant, politiques, journal, protegees) == "arret":
            break
