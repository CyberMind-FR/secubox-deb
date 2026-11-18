# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: action et relevé (#3702)

Le corps de `POST /boxes/{x}/actions/{action}` et du relevé, extrait de `creer_app_admin` : la route HTTP, le vhost d'une box légère
et le moteur de macros appellent les mêmes fonctions (mêmes gardes, même audit). Tout passe par un `Contexte`. `ExecutantApi` est
l'exécutant du moteur en service : une étape `action` passe par `executer_action`, une étape `releve` par `lancer_releve`.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

from pilotage.files import COMMANDE_MESURE, DUREE_DEFAUT_S, DUREE_MAX_S, DUREE_MIN_S, FileDeBoxPleine
from pilotage.inventaire import box_de_ligne
from pilotage.moteur import EchecEtape
from pilotage.operations import CATALOGUE, RE_IDENT, arguments, corps_operate
from pilotage.stockage import HORS_LIGNE_S

ATTENTE_RELEVE_S = 60.0        # une étape `releve` attend au plus ce délai qu'un relevé manuel en cours finisse
DELAI_ACTION_S = 90.0          # OPERATE_RESP d'une action : plus que l'agent n'attend le ctl (60 s, delaiCtl), moins que la file (120 s)
ETATS_REPONSE = ("accepte", "consentement", "refuse")
IDENT_MAX = 128
ERREUR_MAX = 300

log = logging.getLogger("pilotage.admin")


def borne(v, n: int = ERREUR_MAX) -> str:
    return "".join(c for c in str(v)[:n] if c.isprintable())


class ReleveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    duree_s: StrictInt = Field(DUREE_DEFAUT_S, ge=DUREE_MIN_S, le=DUREE_MAX_S)  # entier strict : 60.0, "60", true et NaN sont refusés


class ActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    args: dict = Field(default_factory=dict)
    confirmation: Optional[str] = Field(None, max_length=IDENT_MAX)
    support: Optional[str] = Field(None, pattern="^(?:" + RE_IDENT.pattern + ")$", max_length=64)  # action demandée dans une session de support


@dataclass
class Contexte:
    """Ce dont l'action et le relevé ont besoin ; posé sur `app.state.contexte` par `creer_app_admin`."""
    stockage: object
    files: object
    audit: Callable[[str, dict], None]
    suivi: object
    diffusion: object
    horloge: Callable[[], float] = time.time
    noms_pris: Callable[[], set] = set
    delai_action_s: float = DELAI_ACTION_S
    releves_en_cours: set = field(default_factory=set)   # Box.cle ayant un relevé demandé et pas encore rendu
    taches: set = field(default_factory=set)


async def trouver(ctx: Contexte, ident: str) -> dict:
    if not ident or len(ident) > IDENT_MAX or not ident.isprintable():
        raise HTTPException(404, "box inconnue")
    b = await asyncio.to_thread(ctx.stockage.boite, ident)
    if b is not None:
        return b
    lignes = await asyncio.to_thread(ctx.stockage.boites_par_nom, ident)
    if not lignes:
        raise HTTPException(404, "box inconnue")
    if len(lignes) > 1:
        raise HTTPException(409, {"erreur": "nom ambigu : désigner la box par sa clé", "cles": [b["cle"] for b in lignes]})
    return lignes[0]

def en_ligne(ctx: Contexte, b: dict) -> bool:
    return ctx.horloge() - b["vu_le"] < HORS_LIGNE_S

async def auditer_ou_503(ctx: Contexte, evenement: str, champs: dict) -> None:
    try:
        await asyncio.to_thread(ctx.audit, evenement, champs)
    except Exception:
        log.exception("audit %s impossible : demande refusée", evenement)
        raise HTTPException(503, "audit indisponible") from None

async def auditer(ctx: Contexte, evenement: str, champs: dict) -> None:
    """Après coup (la demande est partie) : un échec d'audit est journalisé, la réponse de la box est rendue quand même."""
    try:
        await asyncio.to_thread(ctx.audit, evenement, champs)
    except Exception:
        log.exception("audit %s impossible", evenement)

async def operer(ctx: Contexte, cle: str, corps: dict) -> Optional[dict]:
    """Dépose l'Operate et attend l'OPERATE_RESP ; None au délai (la requête est retirée de la file si elle n'a pas été servie).
    Rend {etat, job, raison} : la réponse de l'agent telle quelle, ou un refus pour une ERROR (agent de L1, sans exécuteur)."""
    try:
        futur = ctx.files.deposer(cle, {"type": "OPERATE", "body": corps})
    except FileDeBoxPleine:
        raise HTTPException(429, "trop de requêtes en attente pour cette box") from None
    try:
        rep = await asyncio.wait_for(futur, ctx.delai_action_s)
    except asyncio.TimeoutError:
        return None
    c = rep.get("body") if isinstance(rep.get("body"), dict) else {}
    if rep.get("type") == "OPERATE_RESP" and c.get("etat") in ETATS_REPONSE:
        job = c.get("job") if isinstance(c.get("job"), str) and RE_IDENT.fullmatch(c.get("job") or "") else ""
        return {"etat": c["etat"], "job": job, "raison": borne(c.get("raison") or "")}
    return {"etat": "refuse", "job": "", "raison": borne(c.get("err") or c.get("raison") or "réponse inattendue de la box")}

def acteur_de(jwt: dict) -> str:
    return borne(jwt.get("sub", "?"), 64)

async def executer_action(ctx: Contexte, ident: str, action: str, corps: ActionIn, jwt: dict) -> dict:
    """Corps de POST /boxes/{x}/actions/{action}, partagé avec le vhost d'une box légère (#3324 : « Démarrer ») et le moteur de macros."""
    a = CATALOGUE.get(action)
    if a is None:
        raise HTTPException(404, "action inconnue")
    args = arguments(a, corps.args)
    if args is None:
        raise HTTPException(422, {"erreur": "paramètres invalides", "attendus": list(a.parametres)})
    b = await trouver(ctx, ident)
    if not en_ligne(ctx, b):
        raise HTTPException(409, "box hors ligne")
    # confirmation forte (box du propriétaire) : retaper EXACTEMENT le nom de la box ; une confirmation fausse est refusée partout
    if (a.forte and b["reseau"] == "maillage") or corps.confirmation is not None:
        if corps.confirmation != b["nom"]:
            raise HTTPException(400, "confirmation : retapez exactement le nom de la box")
    if b["reseau"] != "maillage" and corps.support is None:
        # I3 (R-L2-47, R-L2-38) : le catalogue d'une box cliente n'est servi que pendant une session de support ouverte et non
        # échue de cette box ; la garde est ici, pas seulement dans la page
        raise HTTPException(409, "box cliente : action seulement pendant une session de support ouverte (champ support)")
    if corps.support is not None and await asyncio.to_thread(ctx.stockage.support_ouvert, b["cle"], corps.support) is None:
        raise HTTPException(409, "session de support non ouverte ou échue")
    if action == "renommer":
        pris = await asyncio.to_thread(lambda: {x["nom"] for x in ctx.stockage.boites()} | set(ctx.noms_pris()))
        if args["nom"] in pris:
            raise HTTPException(409, "nom déjà porté par une box ou un pair connu")
    acteur = acteur_de(jwt)
    # M3 : les paramètres, déjà validés par motif (unité, nom), ne sont jamais secrets : audités
    champs = {"box": b["nom"], "cle": b["cle"], "action": action, "acteur": acteur,
              "args": json.dumps(args, ensure_ascii=False, sort_keys=True)}
    if corps.support is not None:
        champs["support"] = corps.support
    await auditer_ou_503(ctx, "pilotage_action", {**champs, "job": None, "etat": "demande"})   # pas d'audit, pas d'action
    op = await asyncio.to_thread(ctx.stockage.operation_demander, b["cle"], action, args, acteur, corps.support)
    try:
        rep = await operer(ctx, b["cle"], corps_operate(a.commande, args, jwt.get("sub")))
    except HTTPException as e:   # file pleine : rien n'est parti, la demande ne reste pas « demande »
        await asyncio.to_thread(ctx.stockage.operation_reponse, op, "refuse", None, "file de la box pleine")
        await auditer(ctx, "pilotage_action", {**champs, "job": None, "etat": "refuse", "operation": op})
        raise e
    if rep is None:
        await asyncio.to_thread(ctx.stockage.operation_sans_reponse, op)
        await auditer(ctx, "pilotage_action", {**champs, "job": None, "etat": "sans_reponse", "operation": op})
        raise HTTPException(504, "la box n'a pas répondu à temps")
    ligne = await asyncio.to_thread(ctx.stockage.operation_reponse, op, rep["etat"], rep["job"] or None, rep["raison"])
    await auditer(ctx, "pilotage_action", {**champs, "job": rep["job"] or None, "etat": rep["etat"], "operation": op})
    if ligne is not None and ligne["etat"] == "termine":
        # la fin est arrivée avant cette réponse (orpheline fusionnée) : son résultat est audité MAINTENANT, avec l'action
        # désormais connue, une seule fois (I1), puis la suite part
        await ctx.suivi.apres_fin(box_de_ligne(b), ligne)
    ctx.diffusion.publier(b["cle"], "operation", {"box": b["nom"], "cle": b["cle"], "operation": op, "action": action, "args": args,
                                               "acteur": acteur, "etat": rep["etat"], "job": rep["job"], "raison": rep["raison"]})
    return {"operation": op, "box": b["nom"], "cle": b["cle"], "action": action, **rep,
            "operation_etat": ligne["etat"] if ligne else rep["etat"]}


async def lancer_releve(ctx: Contexte, b: dict, duree_s: int, acteur: str) -> asyncio.Task:
    """Demande un relevé de `b` (la box doit être en ligne : à vérifier par l'appelant). 409 si un relevé est déjà en cours, 503 si
    l'audit échoue, 429 si la file de la box est pleine. La tâche rendue range le relevé et libère la réservation."""
    if b["cle"] in ctx.releves_en_cours:
        raise HTTPException(409, "un relevé est déjà en cours pour cette box")
    ctx.releves_en_cours.add(b["cle"])  # réservé avant tout await : pas de second relevé concurrent
    try:
        try:
            await asyncio.to_thread(ctx.audit, "pilotage_releve_demande", {"cle": b["cle"], "acteur": borne(acteur, 64), "duree_s": duree_s})
        except Exception:
            log.exception("audit du relevé impossible : relevé refusé")
            raise HTTPException(503, "audit indisponible") from None
        try:
            futur = ctx.files.deposer(b["cle"], {"type": "OPERATE", "body": {"command": COMMANDE_MESURE, "args": {"duree_s": duree_s}}})
        except FileDeBoxPleine:
            raise HTTPException(429, "trop de requêtes en attente pour cette box") from None
    except BaseException:
        ctx.releves_en_cours.discard(b["cle"])
        raise
    t = asyncio.create_task(suivre_releve(ctx, b["cle"], duree_s, futur))
    ctx.taches.add(t)
    t.add_done_callback(ctx.taches.discard)
    return t


async def suivre_releve(ctx: Contexte, cle: str, duree_s: int, futur: asyncio.Future) -> None:
    try:
        try:
            rep = await futur   # la file borne l'attente (duree_s + 30 s)
        except asyncio.TimeoutError:
            statut, sortie = "expire", {"err": "la box n'a pas rendu le relevé à temps"}
        else:
            corps = rep.get("body") if isinstance(rep.get("body"), dict) else {}
            if rep.get("type") == "OPERATE_RESP":
                statut, sortie = "ok", corps.get("output")
            else:
                statut, sortie = "erreur", {"err": borne(corps.get("err", ""))}
        await asyncio.to_thread(ctx.stockage.releve_enregistrer, cle, duree_s, statut, sortie)
    except asyncio.CancelledError:
        futur.cancel()
        raise
    except Exception:
        log.exception("relevé de %s non rangé", cle)
    finally:
        ctx.releves_en_cours.discard(cle)


def _motif(e: HTTPException) -> str:
    d = e.detail
    if isinstance(d, dict):
        d = d.get("erreur") or "refus"
    return borne(d)


class ExecutantApi:
    """L'`Executant` du moteur en service. Tout refus (HTTPException des gardes, corps invalide) devient un `EchecEtape` lisible :
    l'étape échoue, jamais « erreur interne du moteur ». `attente`/`sonde_s` : sonde de l'attente d'un relevé manuel en cours."""

    def __init__(self, ctx: Contexte, *, attente=asyncio.sleep, sonde_s: float = 1.0, attente_releve_s: float = ATTENTE_RELEVE_S) -> None:
        self.ctx, self.attente, self.sonde_s, self.attente_releve_s = ctx, attente, sonde_s, attente_releve_s

    async def action(self, b: dict, action: str, args: dict, *, confirmation: Optional[str], support: Optional[str],
                     acteur: str) -> dict:
        try:
            corps = ActionIn(args=args, confirmation=confirmation, support=support)
        except ValidationError:
            raise EchecEtape("paramètres de l'étape invalides (confirmation ou session de support)") from None
        try:
            return await executer_action(self.ctx, b["cle"], action, corps, {"sub": acteur})
        except HTTPException as e:
            raise EchecEtape(_motif(e)) from None

    async def releve(self, b: dict, duree_s: int, acteur: str) -> str:
        ctx, cle = self.ctx, b["cle"]
        ligne = await asyncio.to_thread(ctx.stockage.boite, cle)
        if ligne is None or not en_ligne(ctx, ligne):
            raise EchecEtape("box hors ligne")
        limite = ctx.horloge() + self.attente_releve_s
        while cle in ctx.releves_en_cours:          # un relevé manuel en cours : le laisser finir, au plus attente_releve_s
            if ctx.horloge() >= limite:
                raise EchecEtape(f"relevé déjà en cours depuis plus de {int(self.attente_releve_s)} s")
            await self.attente(self.sonde_s)
        try:                                        # aucun await entre la sortie de l'attente et la réservation de lancer_releve
            tache = await lancer_releve(ctx, ligne, duree_s, acteur)
        except HTTPException as e:
            raise EchecEtape(_motif(e)) from None
        await tache
        r = await asyncio.to_thread(ctx.stockage.releve_lire, cle)
        return r["statut"] if r else "erreur"
