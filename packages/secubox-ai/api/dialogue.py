# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dialogue en flux de secubox-ai (onglet Essai) : NDJSON, Continuer, reprise après rechargement (#3583).

Porté du POC gk0 (`essai_flux`) pour l'administration seule : le dialogue public reste sur gk0 (étape 3).
Les noms, l'ordre et les champs des événements NDJSON sont ceux du POC : la page est portée telle quelle.
Chaque dialogue crée un travail (`taches.TRAVAUX`) : une page rechargée s'y raccroche par `/travaux/{id}`.
Une image jointe ne quitte pas la box sans choix explicite du moteur distant ; le moteur local ne lit pas les images
à l'étape 1 (`moteurs.local_lit_images`) : la question est alors refusée aussitôt, sans démarrer de moteur.
Le journal ne reçoit jamais ni la question, ni la réponse, ni les adresses des sources.
"""
import asyncio
import json
import logging
import re
import secrets
import sqlite3
import time

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import StreamingResponse

from secubox_core.auth import require_jwt

from api import memoire, moteurs, reglages
from api.recherche import (LUCIDITE_DEFAUT, consigne_sources, controler_reponse, nom_lucidite, recherche_fiable,
                           regler_lucidite)
from api.taches import COMPTEURS, SANS_RAISONNEMENT, TRAVAUX, FilSuivi, _un_seul_systeme, purger_travaux

log = logging.getLogger("secubox.ai.dialogue")

CONSIGNE_EQUILIBRE = ("Appuie-toi d'abord sur les sources. Tu peux compléter par tes connaissances, en distinguant "
                      "clairement ce qui ne vient pas d'elles.")
CONSIGNE_DELIRE = ("Mode imagination, choisi par l'utilisateur : réponds librement et avec créativité, sans chercher "
                   "l'exactitude. Commence ta réponse par « (imaginé) ». N'affirme jamais qu'un fait inventé est réel.")
IMAGE_ENTREE = re.compile(r"^data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$")
IMAGE_MAX = 4 * 1024 * 1024
QUESTION_MAX = 4000
REFUS_IMAGE_LOCAL = "le modèle local ne lit pas les images : choisissez le moteur distant (gk0) pour cette question"
# Outils de recherche portés (R15 : l'appel de fonctions reste sur gk0) : la recherche préalable n'a lieu que si
# l'un d'eux est actif, comme `schemas_outils(prefs)` non vide dans le POC.
OUTILS_RECHERCHE = ("secubox", "searxng", "wikipedia")

# Réponses coupées à la longueur maximale : leur contexte (consigne, sources, question, réponse déjà écrite) est gardé
# EN MÉMOIRE seulement, 30 min, pour « Continuer » ; jamais sur disque.
SUITES: dict = {}
SUITE_TTL, SUITES_MAX = 1800, 20
CONSIGNE_SUITE = ("Continue ta réponse précédente exactement là où elle s'est arrêtée, au milieu de la phrase s'il le "
                  "faut. Ne répète rien, ne résume pas ce qui précède, n'ajoute pas d'introduction.")


def suite_demandee(corps: dict) -> tuple[dict | None, str]:
    """(contexte gardé, identifiant) si `corps` demande la suite d'une réponse coupée ; 404 si elle a expiré."""
    ident = str(corps.get("suite") or "")
    if not ident:
        return None, ""
    for k in [k for k, s in SUITES.items() if time.time() - s["quand"] > SUITE_TTL]:
        SUITES.pop(k, None)
    s = SUITES.get(ident)
    if s is None:
        raise HTTPException(404, "suite expirée : reposez la question")
    return s, ident


def _recherche_permise(prefs: dict) -> bool:
    o = prefs["outils"]
    return o["mode"] != "jamais" and any(o.get(n) for n in OUTILS_RECHERCHE)


async def _moteur_a_demarrer(force: str | None) -> bool:
    """Vrai si le moteur qui répondra n'est pas encore prêt (la page affiche alors « démarrage »)."""
    e = await moteurs.etat()
    return not e["local"]["pret"] if force == "local" else e["actif"] is None


routeur = APIRouter(prefix="", dependencies=[Depends(require_jwt)])


@routeur.post("/essai/flux")
async def essai_flux(corps: dict = Body(...)):
    """NDJSON : une ligne par étape, puis le texte par morceaux, puis le bilan."""
    prefs = reglages.lire_prefs()
    suite, suite_id = suite_demandee(corps)
    question = suite["question"] if suite else str(corps.get("question") or "")[:QUESTION_MAX].strip()
    # Image jointe : données incluses seulement, JPEG/PNG/WebP, 4 Mo au plus. Elle ne quitte pas la box.
    image = "" if suite else str(corps.get("image") or "")
    if image:
        m = IMAGE_ENTREE.match(image)
        if not m:
            raise HTTPException(422, "image : JPEG, PNG ou WebP, envoyée depuis la page")
        if len(m.group(2)) * 3 // 4 > IMAGE_MAX:
            raise HTTPException(413, "image : 4 Mo au plus")
        question = question or "Décris cette image."
    if not question:
        raise HTTPException(422, "question requise")
    # Réglages par question : appliqués à cette question seulement ; un autre modèle est enregistré dans les
    # préférences, et le moteur local redémarré dessus seulement s'il répond à la question.
    temperature_forcee, modele_change = None, False
    if isinstance(corps.get("reglages"), dict):
        r = corps["reglages"]
        valeurs = {k: r[k] for k in ("max_tokens", "temperature") if r.get(k) is not None}
        prefs = reglages.valider({"generation": valeurs})
        temperature_forcee = r.get("temperature")
        if r.get("modele") and r["modele"] != prefs["moteur"]["modele"]:
            prefs["moteur"]["modele"] = reglages.valider({"moteur": {"modele": r["modele"]}})["moteur"]["modele"]
            reglages.ecrire_prefs({**reglages.lire_prefs(), "moteur": prefs["moteur"]})
            log.info("modele.activer origine=essai")
            modele_change = True
    lucidite = suite["lucidite"] if suite else regler_lucidite(corps.get("lucidite", LUCIDITE_DEFAUT))
    if suite and suite["temperature_forcee"] is not None:
        temperature_forcee = suite["temperature_forcee"]
    # Média joint (ou suite d'une réponse sur un média) : moteur local, sauf moteur distant explicitement forcé.
    # Le choix est lu une fois et passé tel quel : une préférence changée entre-temps n'envoie rien au distant.
    sur_la_box = bool(image) or bool(suite and suite.get("sur_la_box"))
    force = prefs["moteur"]["force"]
    image_au_local = sur_la_box and force != "distant"
    if image_au_local:
        force = "local"
    log.info("essai lucidite=%s (%d) modele=%s", nom_lucidite(lucidite["niveau"]), lucidite["niveau"],
             prefs["moteur"]["modele"])
    purger_travaux()
    travail_id = secrets.token_hex(8)
    TRAVAUX[travail_id] = {"id": travail_id, "question": ("▶ suite : " if suite else "") + question[:300], "evenements": [],
                           "texte": "", "fini": False, "debut": time.time(), "fin": None, "dernier": None, "lecture": None}
    file = FilSuivi(travail_id, time.time())

    async def travail():
        debut, g, sources = time.time(), prefs["generation"], []
        recherche, bloc_sources = None, ""
        await file.put({"etape": "lucidite", **lucidite})
        contenu = [{"type": "text", "text": question}, {"type": "image_url", "image_url": {"url": image}}] if image else question
        messages = [{"role": "system", "content": prefs["comportement"]["consigne"]}, {"role": "user", "content": contenu}]
        if image:
            await file.put({"etape": "image", "octets": len(image) * 3 // 4})
        if image_au_local and not moteurs.local_lit_images():
            # Aucun démarrage du moteur pour une question qu'il ne saurait pas lire.
            raise HTTPException(409, REFUS_IMAGE_LOCAL)
        temperature = lucidite["temperature"]
        if lucidite["mode"] == "delire":
            messages[0]["content"] += "\n\n" + CONSIGNE_DELIRE
        # Mémoire locale : passages utiles donnés comme données citées.
        souvenirs = []
        if not suite and prefs["memoire"]["actif"]:
            souvenirs = await asyncio.to_thread(memoire.memoire_chercher, question, prefs["memoire"]["caracteres"], True)
            if souvenirs:
                messages.insert(1, {"role": "system", "content": memoire.CONSIGNE_MEMOIRE + memoire.bloc_memoire(souvenirs)})
            await file.put({"etape": "memoire", "souvenirs": [{"id": s["id"], "titre": s["titre"], "genre": s["genre"]}
                                                               for s in souvenirs]})
            proposition = memoire.DECLENCHEUR_MEMOIRE.match(question)
            if proposition:
                await file.put({"etape": "proposition_memoire", "texte": proposition.group(2).strip()[:2000]})
        if suite:
            sources.extend(suite["sources"])
            recherche, bloc_sources = suite["recherche"], suite["bloc"]
            await file.put({"etape": "suite", "caracteres": len(suite["reponse"])})
        # Avec une image, la question porte sur elle : pas de recherche web (ses mots ne partent pas vers les moteurs).
        if not suite and not image and lucidite["mode"] != "delire" and _recherche_permise(prefs):
            await file.put({"etape": "recherche"})
            recherche, bloc = await recherche_fiable(question, prefs, sources, file)
            await file.put({"etape": "sources", "etat": recherche, "sources": sources, "caracteres": len(bloc)})
            if recherche != "ok" and lucidite["mode"] == "equilibre":
                messages[0]["content"] += ("\n\nAucune source trouvée : dis-le, et signale que ta réponse vient de tes "
                                           "seules connaissances.")
            elif recherche != "ok":
                texte = ("La recherche est indisponible pour le moment : je préfère ne pas répondre sans source."
                         if recherche == "indisponible"
                         else "Je n'ai pas réussi à lire cette adresse : je préfère ne rien inventer." if recherche == "illisible"
                         else "Je n'ai trouvé aucune source qui parle de ce sujet : je ne sais pas.")
                log.info("chat.sans_source recherche=%s", recherche)
                await file.put({"etape": "texte", "morceau": texte})
                await file.put({"etape": "bilan", "modele_appele": False, "recherche": recherche,
                                "duree_s": round(time.time() - debut, 1)})
                return
            if recherche == "ok":
                messages.insert(1, {"role": "system", "content": consigne_sources(bloc) if lucidite["mode"] == "lucide"
                                    else CONSIGNE_EQUILIBRE + "\n" + bloc})
                bloc_sources = bloc
        if souvenirs and bloc_sources:
            bloc_sources += memoire.bloc_memoire(souvenirs)     # une adresse citée depuis la mémoire n'est pas « non vérifiée »
        if temperature_forcee is not None:
            temperature = temperature_forcee
        base = suite["messages"] if suite else list(messages)
        if suite:
            messages = base + [{"role": "assistant", "content": suite["reponse"]}, {"role": "user", "content": CONSIGNE_SUITE}]
        moteur = await choisir_moteur(force, modele_change)
        COMPTEURS["requetes"] = COMPTEURS.get("requetes", 0) + 1
        p = await moteurs.props(moteur)
        contexte = moteurs.contexte_de(p)
        await file.put({"etape": "generation", "modele": moteurs.modele_de(moteur, p), "moteur": moteur.nom,
                        "contexte": contexte, "max_tokens": g["max_tokens"]})
        charge = {"chat_template_kwargs": SANS_RAISONNEMENT, "messages": _un_seul_systeme(messages), "stream": True,
                  "stream_options": {"include_usage": True}, "temperature": temperature, "top_p": lucidite["top_p"],
                  "max_tokens": g["max_tokens"], "return_progress": True}
        usage, timings, fin, produits, premier = {}, {}, None, 0, None
        reflexion, dernier_signe = 0, 0.0
        morceaux = []

        async def signe_de_vie():
            # Lecture des sources puis raisonnement : de longues secondes sans un octet ; un proxy coupe alors le
            # flux. Un signe toutes les 5 s.
            while True:
                await asyncio.sleep(5)
                await file.put({"etape": "reflexion", "tokens": reflexion})
        veille = asyncio.create_task(signe_de_vie())
        try:
            async with moteur.client() as c, c.stream("POST", "/v1/chat/completions", json=charge) as r:
                if r.status_code != 200:
                    raise HTTPException(502, REFUS_IMAGE_LOCAL if sur_la_box and moteur.nom == "local"
                                        else "le moteur a refusé la requête")
                async for ligne in r.aiter_lines():
                    if not ligne.startswith("data: ") or ligne == "data: [DONE]":
                        continue
                    m = json.loads(ligne[6:])
                    usage, timings = m.get("usage") or usage, m.get("timings") or timings
                    pp = m.get("prompt_progress")
                    if pp and pp.get("total") and time.time() - dernier_signe > .7:
                        # Lecture du contexte (sources, question) avant le premier mot : 30 000 jetons prennent des minutes.
                        dernier_signe = time.time()
                        await file.put({"etape": "lecture", "fait": pp.get("processed", 0), "total": pp["total"],
                                        "cache": pp.get("cache", 0), "ms": pp.get("time_ms")})
                    for choix in m.get("choices", []):
                        fin = choix.get("finish_reason") or fin
                        morceau = (choix.get("delta") or {}).get("content")
                        if (choix.get("delta") or {}).get("reasoning_content") and not morceau:
                            # Un modèle qui raisonne se tait de longues secondes : un signe de vie toutes les 2 s.
                            reflexion += 1
                            if time.time() - dernier_signe > 2:
                                dernier_signe = time.time()
                                await file.put({"etape": "reflexion", "tokens": reflexion})
                        if morceau:
                            premier = premier or time.time()
                            produits += 1
                            morceaux.append(morceau)
                            await file.put({"etape": "texte", "morceau": morceau, "tokens": produits,
                                            "vitesse": round(timings["predicted_per_second"], 1)
                                            if timings.get("predicted_per_second") else None})
        finally:
            veille.cancel()
        vitesse = timings.get("predicted_per_second")
        COMPTEURS["derniere_vitesse"] = round(vitesse, 1) if vitesse else None
        texte_total = (suite["reponse"] if suite else "") + "".join(morceaux)
        propre = texte_total
        if bloc_sources:
            propre, retirees, annees = controler_reponse(texte_total, bloc_sources)
            await file.put({"etape": "controle", "texte": propre, "adresses_retirees": len(retirees),
                            "annees_non_trouvees": annees})
        log.info("chat tokens=%s sources=%d duree_s=%.1f", usage.get("total_tokens"), len(sources), time.time() - debut)
        nouvelle = None
        if fin == "length" and (usage.get("total_tokens") or 0) + 64 < contexte:
            nouvelle = suite_id or secrets.token_hex(8)
            while len(SUITES) >= SUITES_MAX and nouvelle not in SUITES:
                SUITES.pop(next(iter(SUITES)))
            SUITES[nouvelle] = {"question": question, "messages": base, "reponse": texte_total, "bloc": bloc_sources,
                                "recherche": recherche, "sources": list(sources), "lucidite": lucidite,
                                "temperature_forcee": temperature_forcee, "sur_la_box": sur_la_box, "quand": time.time()}
        elif suite_id:
            SUITES.pop(suite_id, None)
        if morceaux:
            try:
                await asyncio.to_thread(memoire.historique_ajouter, "dialogue", question, propre,
                                        [s["url"] for s in sources if s.get("url")])
            except (sqlite3.Error, OSError) as e:     # l'historique manqué ne prive jamais du bilan (ni de la suite)
                log.warning("historique.echec cause=%s", type(e).__name__)
        await file.put({"etape": "bilan", "modele_appele": True, "recherche": recherche,
                        "tokens_question": usage.get("prompt_tokens"), "tokens_reponse": usage.get("completion_tokens"),
                        "tokens_total": usage.get("total_tokens"), "contexte": contexte, "max_tokens": g["max_tokens"],
                        "vitesse": COMPTEURS["derniere_vitesse"], "fin": fin, "suite": nouvelle,
                        "premier_token_s": round(premier - debut, 1) if premier else None,
                        "duree_s": round(time.time() - debut, 1)})

    async def choisir_moteur(force, modele_change):
        """Le moteur qui répond, prêt ; « démarrage » annoncé s'il faut l'attendre. Un modèle changé redémarre le
        moteur local seulement s'il répond à la question, et rien ne part avant que le nouveau modèle réponde."""
        if modele_change and (await moteurs.choisir(force)).nom == "local":
            await file.put({"etape": "moteur", "etat": "démarrage"})
            return await moteurs.changer_modele_local()
        if await _moteur_a_demarrer(force):
            await file.put({"etape": "moteur", "etat": "démarrage"})
        moteur = await moteurs.assurer_moteur(force=force)
        if modele_change and moteur.nom == "local":       # distant écarté en route : repli sur le local
            await file.put({"etape": "moteur", "etat": "démarrage"})
            moteur = await moteurs.changer_modele_local()
        return moteur

    async def mener():
        COMPTEURS["en_cours"] += 1
        try:
            await file.put({"etape": "travail", "id": travail_id})
            await travail()
        except HTTPException as e:
            await file.put({"etape": "erreur", "message": e.detail})
        except (httpx.HTTPError, ValueError, OSError) as e:
            log.warning("moteur.echec cause=%s", type(e).__name__)
            await file.put({"etape": "erreur", "message": "moteur injoignable, peut-être arrêté par sa limite mémoire"})
        except Exception as e:  # noqa: BLE001 — aucun travail ne doit rester « en cours » ; cause seule au journal
            log.error("dialogue.echec cause=%s", type(e).__name__)
            await file.put({"etape": "erreur", "message": f"échec du dialogue ({type(e).__name__})"})
        finally:
            COMPTEURS["en_cours"] -= 1
            COMPTEURS["derniere_activite"] = time.time()
            await file.put(None)

    async def flux():
        # Le travail vit hors de la requête : une page fermée ou rechargée ne l'arrête pas (reprise par /travaux).
        tache = asyncio.create_task(mener())
        TRAVAUX[travail_id]["_tache"] = tache
        debut = time.time()
        while (evt := await file.get()) is not None:
            evt.setdefault("t", round(time.time() - debut, 1))
            yield json.dumps(evt, ensure_ascii=False) + "\n"
        await asyncio.wait({tache})     # arrêté par « Tout arrêter » : fin du flux, sans exception

    return StreamingResponse(flux(), media_type="application/x-ndjson")
