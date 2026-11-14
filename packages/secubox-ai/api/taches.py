# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tâches de fond, travaux en cours et « Tout arrêter » de secubox-ai (#3583), portés du POC gk0.

Tout reste en mémoire (rien sur disque). Le journal ne reçoit jamais ni question, ni réponse, ni titre.
La génération d'image n'existe pas à l'étape 1 : `tout_arreter` ne connaît que les tâches et les travaux.
"""
import asyncio
import json
import logging
import re
import secrets
import time
from typing import Callable

import httpx
from fastapi import APIRouter, Depends, HTTPException

from secubox_core.auth import require_jwt

from api.moteurs import assurer_moteur

log = logging.getLogger("secubox.ai.taches")

SANS_RAISONNEMENT = {"enable_thinking": False}

# Dialogues de l'administration : fil d'événements gardé en mémoire 30 min, pour qu'une page rechargée s'y raccroche.
TRAVAUX: dict = {}
TRAVAUX_TTL, TRAVAUX_MAX = 1800, 20

# Tâches de fond (documents, agents) : suivies par la page, arrêtables.
TACHES: dict = {}
TACHES_MAX = 30

# Le moteur ne se met pas en veille tant que `en_cours` > 0 (lu par la veille, tâche suivante).
COMPTEURS = {"en_cours": 0, "derniere_activite": 0.0}

# Crochet vers l'historique (tâche suivante) : `f(genre, titre, texte, sources=())`. Sans lui, rien n'est gardé.
HISTORIQUE_AJOUTER: Callable | None = None


def historique_ajouter(genre, titre, texte, sources=()):
    if HISTORIQUE_AJOUTER is not None:
        HISTORIQUE_AJOUTER(genre, titre, texte, sources)


class FilSuivi(asyncio.Queue):
    """File du flux NDJSON qui horodate chaque événement et le recopie dans le fil du travail (si suivi)."""

    def __init__(self, ident, debut):
        super().__init__()
        self.ident, self.debut = ident, debut

    async def put(self, evt):
        tr = TRAVAUX.get(self.ident) if self.ident else None
        if evt is not None:
            evt.setdefault("t", round(time.time() - self.debut, 1))
            if tr is not None:
                tr["evenements"].append(evt)
                if evt.get("etape") == "texte":
                    tr["texte"] += evt.get("morceau", "")
                tr["dernier"] = evt.get("etape")
                if evt.get("etape") == "lecture":
                    tr["lecture"] = [evt.get("fait"), evt.get("total")]
        elif tr is not None:
            tr.update(fini=True, fin=time.time())
        await super().put(evt)


def purger_travaux():
    for k in [k for k, x in TRAVAUX.items() if x["fini"] and time.time() - x["fin"] > TRAVAUX_TTL]:
        TRAVAUX.pop(k, None)
    while len(TRAVAUX) > TRAVAUX_MAX:
        TRAVAUX.pop(next(iter(TRAVAUX)))


def nouvelle_tache(genre, titre):
    while len(TACHES) >= TACHES_MAX:
        TACHES.pop(next(iter(TACHES)))
    ident = secrets.token_hex(8)
    TACHES[ident] = {"id": ident, "genre": genre, "titre": titre, "etat": "en_cours", "etapes": [], "resultat": "",
                     "sources": [], "image": None, "debut": time.time(), "fin": None}
    return ident


def etape(t, texte):
    e = TACHES[t]["etapes"]
    if e and e[-1]["etat"] == "en_cours":
        e[-1]["etat"] = "fait"
    e.append({"texte": texte, "etat": "en_cours"})


def finir(t, etat, resultat):
    # Les formules creuses du modèle (« Voici le résumé : ») ne font pas partie du résultat.
    resultat = re.sub(r"(?im)\A\s*(voici|voil[àa])\b[^\n]*:\s*\n+", "", resultat or "")
    tache = TACHES[t]
    for e in tache["etapes"]:
        if e["etat"] == "en_cours":
            e["etat"] = "fait" if etat == "fini" else etat
    tache.update(etat=etat, resultat=resultat, fin=time.time(), progression=None)
    if etat == "fini" and resultat:
        historique_ajouter(tache["genre"], tache["titre"], resultat, [s["url"] for s in tache["sources"] if s.get("url")])


def lancer_tache(t, coro, delai):
    async def courir():
        try:
            await asyncio.wait_for(coro, delai)
        except asyncio.TimeoutError:
            # Ce qui est fait reste affiché (et gardé dans l'historique) : un dépassement ne jette jamais le travail.
            deja = TACHES[t]["resultat"]
            finir(t, "echec", (deja + "\n\n" if deja else "") + "(Arrêté : la tâche a dépassé sa durée maximale ; ce qui précède est fait.)")
            if deja:
                historique_ajouter(TACHES[t]["genre"], TACHES[t]["titre"] + " (partiel)", deja)
        except asyncio.CancelledError:
            deja = TACHES[t]["resultat"]
            finir(t, "arrete", (deja + "\n\n(Arrêté à la demande ; ce qui précède est fait.)") if deja else "Arrêté à la demande.")
            if deja:
                historique_ajouter(TACHES[t]["genre"], TACHES[t]["titre"] + " (partiel)", deja)
        except HTTPException as e:
            finir(t, "echec", str(e.detail))
        except (httpx.HTTPError, KeyError, ValueError, OSError) as e:
            finir(t, "echec", f"Échec ({type(e).__name__}).")
    TACHES[t]["_tache"] = asyncio.create_task(courir())


def _un_seul_systeme(messages):
    """Plusieurs gabarits (Gemma…) refusent deux messages « system » : on les réunit en tête."""
    systeme = "\n\n".join(m["content"] for m in messages if m.get("role") == "system")
    return ([{"role": "system", "content": systeme}] if systeme else []) + [m for m in messages if m.get("role") != "system"]


async def demander_modele(systeme, utilisateur, max_tokens=400, t=None):
    """Un appel au moteur de texte, sans raisonnement caché, en flux : la tâche `t` suit la lecture du contexte puis
    l'écriture (TACHES[t]["progression"]). Le moteur ne se met pas en veille pendant l'appel."""
    moteur = await assurer_moteur()
    COMPTEURS["en_cours"] += 1
    morceaux, produits = [], 0
    try:
        if t in TACHES:
            TACHES[t]["progression"] = {"phase": "attente", "fait": 0, "total": 0}
        async with moteur.client(900) as c, c.stream("POST", "/v1/chat/completions", json={
                "chat_template_kwargs": SANS_RAISONNEMENT, "stream": True, "temperature": 0.2, "max_tokens": max_tokens,
                "return_progress": True,
                "messages": _un_seul_systeme([{"role": "system", "content": systeme},
                                              {"role": "user", "content": utilisateur}])}) as r:
            if r.status_code != 200:
                raise HTTPException(502, "le moteur a refusé la requête")
            async for ligne in r.aiter_lines():
                if not ligne.startswith("data: ") or ligne == "data: [DONE]":
                    continue
                m = json.loads(ligne[6:])
                pp = m.get("prompt_progress")
                if pp and pp.get("total") and t in TACHES:
                    TACHES[t]["progression"] = {"phase": "lecture", "fait": pp.get("processed", 0), "total": pp["total"],
                                                "ms": pp.get("time_ms")}
                for choix in m.get("choices", []):
                    bout = (choix.get("delta") or {}).get("content")
                    if bout:
                        morceaux.append(bout)
                        produits += 1
                        if t in TACHES:
                            TACHES[t]["progression"] = {"phase": "ecriture", "fait": produits, "total": max_tokens}
        return re.sub(r"(?s)<think>.*?</think>", "", "".join(morceaux)).strip()
    finally:
        COMPTEURS["en_cours"] -= 1
        COMPTEURS["derniere_activite"] = time.time()


routeur = APIRouter(prefix="", dependencies=[Depends(require_jwt)])


@routeur.get("/taches/{t}")
async def tache_lire(t: str):
    if t not in TACHES:
        raise HTTPException(404, "tâche inconnue")
    return {k: v for k, v in TACHES[t].items() if not k.startswith("_")}


@routeur.post("/taches/{t}/arreter")
async def tache_arreter(t: str):
    if t not in TACHES:
        raise HTTPException(404, "tâche inconnue")
    if TACHES[t].get("_tache") and not TACHES[t]["_tache"].done():
        TACHES[t]["_tache"].cancel()
    return {"ok": True}


@routeur.get("/travaux")
async def travaux_liste():
    """Ce qui est en cours ou vient de finir : dialogues et tâches (documents, agents)."""
    purger_travaux()
    maintenant, liste = time.time(), []
    for x in TRAVAUX.values():
        etat = ("fini" if x["fini"] else f"lecture {x['lecture'][0]} / {x['lecture'][1]} jetons" if x["dernier"] == "lecture"
                and x.get("lecture") else f"écrit {len(x['texte'])} caractères" if x["texte"] else x["dernier"] or "départ")
        prog = ({"phase": "lecture", "fait": x["lecture"][0], "total": x["lecture"][1]} if x["dernier"] == "lecture" and x.get("lecture")
                else {"phase": "ecriture", "fait": len(x["texte"]), "total": 0} if x["texte"] and not x["fini"] else None)
        liste.append({"id": x["id"], "genre": "dialogue", "titre": x["question"][:120], "fini": x["fini"], "etat": etat,
                      "debut": x["debut"], "depuis_s": round(maintenant - x["debut"]), "progression": prog})
    for x in TACHES.values():
        if x["fin"] is None or maintenant - x["fin"] < TRAVAUX_TTL:
            liste.append({"id": x["id"], "genre": x["genre"], "titre": x["titre"], "fini": x["etat"] != "en_cours",
                          "etat": x["etat"] if x["etat"] != "en_cours" else (x["etapes"][-1]["texte"] if x["etapes"] else "départ"),
                          "debut": x["debut"], "depuis_s": round(maintenant - x["debut"]),
                          "progression": x.get("progression"), "global": x.get("global")})
    return {"travaux": sorted(liste, key=lambda x: -x["debut"])}


@routeur.get("/travaux/{ident}")
async def travail_lire(ident: str, depuis: int = 0):
    x = TRAVAUX.get(ident)
    if x is None:
        raise HTTPException(404, "travail inconnu ou expiré")
    return {"question": x["question"], "evenements": x["evenements"][max(0, depuis):], "n": len(x["evenements"]), "fini": x["fini"]}


@routeur.post("/travaux/{ident}/arreter")
async def travail_arreter(ident: str):
    x = TRAVAUX.get(ident)
    if x is None:
        raise HTTPException(404, "travail inconnu ou expiré")
    if x.get("_tache") and not x["_tache"].done():
        x["_tache"].cancel()
        x.update(fini=True, fin=time.time(), dernier="arrêté")
    return {"ok": True}


@routeur.post("/tout-arreter")
async def tout_arreter():
    """Arrête tout ce que l'administration a lancé : dialogues, analyses, agents."""
    n = 0
    for x in TRAVAUX.values():
        if x.get("_tache") and not x["_tache"].done():
            x["_tache"].cancel()
            x.update(fini=True, fin=time.time(), dernier="arrêté")
            n += 1
    for x in TACHES.values():
        if x.get("_tache") and not x["_tache"].done():
            x["_tache"].cancel()
            n += 1
    log.info("tout_arreter arretes=%d", n)
    return {"arretes": n}
