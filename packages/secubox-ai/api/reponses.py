# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Réponses de la veille V2 (#3723, V2 § 10.3) : propositions, actions, décisions humaines, suspension.

Toute route est gardée par `require_jwt` (administrateur réel). L'API ne détient PAS la clé `ai-ban` et n'envoie
rien à gk2 : elle LIT veille.db (lecture seule) et n'y ÉCRIT que les décisions humaines (`approbations`,
`propositions.etat`, suspension), chacune en UNE transaction courte avec sa ligne `audit_chaine` (relayée dans
audit.log par la veille : le profil de l'API lui interdit ce journal). Elle n'ouvre la base qu'en `mode=rw` : jamais
créée ici, ni migrée (503 tant que la veille ne l'a pas préparée). SQLite hors de la boucle (`asyncio.to_thread`).

Listes : curseur opaque (`horodatage|id` de la dernière ligne rendue), 100 lignes par défaut, 500 au plus.
"""
import asyncio
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, StrictInt

from secubox_core.auth import require_jwt

from api import radar
from veille import apprentissage, decisions

routeur = APIRouter(prefix="", dependencies=[Depends(require_jwt)])

ETATS = ("proposee", "approuvee", "refusee", "expiree", "envoyee", "faite", "refusee_gk2", "echec")
COLONNES_PROP = ("id", "version", "dossier_id", "incident_id", "analyse_id", "geste", "cible", "duree_s", "mode",
                 "niveau", "reference", "politique", "motif", "etat", "expire_le", "cree_le", "maj_le")
COLONNES_ACTION = ("id", "proposition_id", "geste", "cible", "mode", "id_cible_gk2", "etat", "jti", "cle", "code_http",
                   "motif", "reponse_json", "id_gk2", "fin_gk2", "envoyee_le", "repondue_le", "rapprochee_le")
_RE_CURSEUR = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\|([A-Za-z0-9-]{1,64})$")
_RE_ACTEUR = re.compile(r"^[A-Za-z0-9._@:-]{1,64}$")


class Decision(BaseModel):
    model_config = {"extra": "forbid"}

    version: StrictInt


def _indisponible():
    return HTTPException(503, detail={"motif": "veille_indisponible"})


def _ouvrir_ecriture():
    """veille.db en lecture-écriture SANS création (mode=rw) ; tables de l'exécuteur exigées (migration 0007)."""
    chemin = radar.chemin_veille()
    if not chemin.is_file():
        raise _indisponible()
    try:
        db = sqlite3.connect(chemin.resolve().as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None)
        db.execute("PRAGMA busy_timeout = 5000")
        db.execute("PRAGMA foreign_keys = ON")
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'executeur_etat'").fetchone():
            db.close()
            raise _indisponible()
        return db
    except sqlite3.Error:
        raise _indisponible() from None


def _lecture():
    db = radar._ouvrir_lecture()
    if db is None:
        raise _indisponible()
    return db


def _acteur(user) -> str:
    sub = (user or {}).get("sub") if isinstance(user, dict) else None
    return sub if isinstance(sub, str) and _RE_ACTEUR.fullmatch(sub) else "?"


def _curseur(texte: Optional[str]):
    if texte is None:
        return None
    m = _RE_CURSEUR.fullmatch(texte)
    if not m:
        raise HTTPException(422, detail={"motif": "curseur"})
    return m.group(1), m.group(2)


def _page(db, table, colonnes, champ_temps, curseur, limite, filtre="", params=()):
    sql = f"SELECT {', '.join(colonnes)} FROM {table} WHERE 1 = 1 {filtre}"
    args = list(params)
    if curseur:
        sql += f" AND ({champ_temps} < ? OR ({champ_temps} = ? AND id < ?))"
        args += [curseur[0], curseur[0], curseur[1]]
    sql += f" ORDER BY {champ_temps} DESC, id DESC LIMIT ?"
    lignes = [dict(zip(colonnes, r)) for r in db.execute(sql, (*args, limite + 1)).fetchall()]
    suite = None
    if len(lignes) > limite:
        lignes = lignes[:limite]
        suite = f"{lignes[-1][champ_temps]}|{lignes[-1]['id']}"
    return lignes, suite


def _action_vue(a: dict) -> dict:
    brut = a.pop("reponse_json", None)
    try:
        a["reponse"] = json.loads(brut) if brut else None
    except ValueError:
        a["reponse"] = None
    return a


def _executer(fonction, ecriture=False):
    def faire():
        db = _ouvrir_ecriture() if ecriture else _lecture()
        try:
            return fonction(db)
        except sqlite3.OperationalError:
            raise _indisponible() from None
        finally:
            db.close()
    return asyncio.to_thread(faire)


@routeur.get("/propositions")
async def propositions(etat: Optional[str] = None, curseur: Optional[str] = None,
                       limite: int = Query(100, ge=1, le=500)):
    if etat is not None and etat not in ETATS:
        raise HTTPException(422, detail={"motif": "etat"})
    c = _curseur(curseur)

    def lire(db):
        lignes, suite = _page(db, "propositions", COLONNES_PROP, "cree_le", c, limite,
                              "AND etat = ?" if etat else "", (etat,) if etat else ())
        return {"propositions": lignes, "curseur": suite}
    return await _executer(lire)


@routeur.get("/propositions/{pid}")
async def proposition(pid: str):
    def lire(db):
        r = db.execute(f"SELECT {', '.join(COLONNES_PROP)} FROM propositions WHERE id = ?", (pid,)).fetchone()
        if r is None:
            raise HTTPException(404, detail={"motif": "inconnue"})
        approbations = [dict(zip(("version", "acteur", "decision", "cree_le"), x)) for x in db.execute(
            "SELECT version, acteur, decision, cree_le FROM approbations WHERE proposition_id = ? ORDER BY cree_le",
            (pid,)).fetchall()]
        a = db.execute(f"SELECT {', '.join(COLONNES_ACTION)} FROM actions WHERE proposition_id = ?",
                       (pid,)).fetchone()
        return {"proposition": dict(zip(COLONNES_PROP, r)), "approbations": approbations,
                "action": _action_vue(dict(zip(COLONNES_ACTION, a))) if a else None}
    return await _executer(lire)


@routeur.get("/actions")
async def actions(curseur: Optional[str] = None, limite: int = Query(100, ge=1, le=500)):
    c = _curseur(curseur)

    def lire(db):
        lignes, suite = _page(db, "actions", COLONNES_ACTION, "envoyee_le", c, limite)
        return {"actions": [_action_vue(a) for a in lignes], "curseur": suite}
    return await _executer(lire)


def _json_etat(db, cle):
    try:
        v = json.loads(decisions.lire_etat(db, cle) or "null")
    except ValueError:
        v = None
    return v


def _vue_etat(db) -> dict:
    releve = _json_etat(db, "ai_etat") or {}
    politique = _json_etat(db, "politique") or {}
    gk2 = releve.get("plafonds_par_geste") if isinstance(releve, dict) else None
    gk3 = politique.get("plafonds") if isinstance(politique, dict) else None
    plafonds = {}
    for g in sorted(set(gk2 or {}) | set(gk3 or {})):
        plafonds[g] = {"gk2": (gk2 or {}).get(g), "gk3": (gk3 or {}).get(g)}
    s = decisions.suspension(db)
    s["politique"] = bool(isinstance(politique, dict) and politique.get("automatique_suspendu"))
    observation = isinstance(politique, dict) and politique.get("mode") == "observation"
    cle = _json_etat(db, "cle_ai_ban") or {"etat": "inconnu"}
    refus = _json_etat(db, "cle_refusee")
    if isinstance(cle, dict) and isinstance(refus, dict):
        cle = {**cle, "refusee": refus}          # gk2 a refusé la clé (401/403) depuis le dernier geste réussi
    clic = db.execute("SELECT COUNT(*) FROM propositions WHERE etat = 'proposee' AND mode = 'clic'").fetchone()[0]
    auto = db.execute("SELECT COUNT(*) FROM propositions WHERE etat = 'proposee' AND mode = 'auto'").fetchone()[0]
    bloque = s["suspendu"] or s["politique"]
    garde = _json_etat(db, "garde_espace") or {"etat": "inconnu"}     # écrite par la veille (#3725)
    return {"suspension": s, "cle_ai_ban": cle, "garde_espace": garde,
            "sade_mode": releve.get("sade_mode") if isinstance(releve, dict) else None,
            "releve_lu_le": releve.get("lu_le") if isinstance(releve, dict) else None,
            "mode": politique.get("mode") if isinstance(politique, dict) else None, "plafonds": plafonds,
            "envois_en_attente": db.execute("SELECT COUNT(*) FROM actions WHERE etat = 'envoi'").fetchone()[0],
            # À décider : les clics, plus les propositions d'office tant que l'automatique est suspendu (elles
            # n'attendent plus qu'un administrateur). `auto_en_attente` les compte à part dans tous les cas.
            "a_decider": clic + (auto if bloque else 0), "auto_en_attente": auto,
            "observation": observation, "partages_7j": _partages_7j(db)}


def _partages_7j(db) -> dict:
    """Indicateurs partagés au maillage par V2 sur 7 jours (#3724). Les retours des pairs (revu, contenu) ne remontent
    pas jusqu'à gk3 : null, jamais un zéro inventé."""
    depuis = (_maintenant() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    n = db.execute("SELECT COUNT(*) FROM propositions WHERE geste = 'partager' AND etat = 'faite' AND maj_le >= ?",
                   (depuis,)).fetchone()[0]
    return {"partages": n, "revus": None, "contenus": None}


@routeur.get("/veille/etat")
async def veille_etat():
    return await _executer(_vue_etat)


def _maintenant():
    return datetime.now(timezone.utc)


async def _decider(pid: str, corps: Decision, user: dict, decision: str):
    def ecrire(db):
        try:
            return decisions.decider(db, pid, corps.version, _acteur(user), decision, _maintenant())
        except decisions.RefusDecision as e:
            raise HTTPException(e.statut, detail={"motif": e.motif}) from None
    return await _executer(ecrire, ecriture=True)


@routeur.post("/propositions/{pid}/approuver")
async def approuver(pid: str, corps: Decision, user: dict = Depends(require_jwt)):
    return await _decider(pid, corps, user, "approuver")


@routeur.post("/propositions/{pid}/refuser")
async def refuser(pid: str, corps: Decision, user: dict = Depends(require_jwt)):
    return await _decider(pid, corps, user, "refuser")


@routeur.post("/veille/suspendre")
async def veille_suspendre(user: dict = Depends(require_jwt)):
    def ecrire(db):
        decisions.suspendre(db, _acteur(user), _maintenant())
        return {"suspension": decisions.suspension(db)}
    return await _executer(ecrire, ecriture=True)


@routeur.post("/veille/reprendre")
async def veille_reprendre(user: dict = Depends(require_jwt)):
    def ecrire(db):
        decisions.reprendre(db, _acteur(user), _maintenant())
        return {"suspension": decisions.suspension(db)}
    return await _executer(ecrire, ecriture=True)


COLONNES_FILTRE = ("id", "outil", "cve", "dossier_id", "etat", "code_http", "motif", "touches_protegees", "envoye_le",
                   "essai_depuis", "confirme_par", "maj_le")


@routeur.get("/filtres")
async def filtres():
    """Filtres WAF d'office (#3723, carte 4) et état de l'apprentissage (nombres, ou null si inconnus)."""
    def lire(db):
        try:
            lignes = [dict(zip(COLONNES_FILTRE, r)) for r in db.execute(
                f"SELECT {', '.join(COLONNES_FILTRE)} FROM filtres ORDER BY envoye_le DESC LIMIT 500").fetchall()]
        except sqlite3.OperationalError:
            lignes = None
        return {"filtres": lignes, "etat": apprentissage.etat_apprentissage(db),
                "critere_legitime": "non_mesurable_depuis_gk3"}
    return await _executer(lire)


@routeur.get("/filtres/suggestions")
async def filtres_suggestions():
    """Suggestions d'empreintes (jamais appliquées) ; null si le fichier n'existe pas encore."""
    def lire():
        try:
            return json.loads(apprentissage.chemin_suggestions().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"suggestions": None}
    return await asyncio.to_thread(lire)


@routeur.post("/filtres/{fid}/confirmer")
async def filtre_confirmer(fid: str, user: dict = Depends(require_jwt)):
    def ecrire(db):
        try:
            return decisions.confirmer_filtre(db, fid, _acteur(user), _maintenant())
        except decisions.RefusDecision as e:
            raise HTTPException(e.statut, detail={"motif": e.motif}) from None
    return await _executer(ecrire, ecriture=True)


# ---- console #3724 : décisions humaines de l'onglet Dossier (écrites ici, appliquées par la veille) ----
async def _demande(fonction, ident: str, user: dict):
    def ecrire(db):
        try:
            return fonction(db, ident, _acteur(user), _maintenant())
        except decisions.RefusDecision as e:
            raise HTTPException(e.statut, detail={"motif": e.motif}) from None
    return await _executer(ecrire, ecriture=True)


@routeur.post("/dossiers/{did}/redescendre")
async def dossier_redescendre(did: str, user: dict = Depends(require_jwt)):
    """Redescendre le niveau à `observer` : la décision est écrite (auditée, relayée), la veille l'applique."""
    return await _demande(decisions.demander_redescente, did, user)


@routeur.post("/dossiers/{did}/analyser")
async def dossier_analyser(did: str, user: dict = Depends(require_jwt)):
    """Analyser à nouveau : un travail `analyser` déposé (un seul en attente par dossier)."""
    return await _demande(decisions.demander_analyse, did, user)


@routeur.post("/actions/{aid}/defaire")
async def action_defaire(aid: str, user: dict = Depends(require_jwt)):
    """Défaire une action V2 : levée `unban` approuvée (référence = la proposition du geste), envoyée par
    l'exécuteur après revalidation. 409 si l'action n'a pas été posée par V2, n'est pas faite, est échue ou levée."""
    return await _demande(decisions.demander_defaire, aid, user)
