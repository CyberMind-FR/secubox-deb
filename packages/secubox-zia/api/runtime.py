# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ZIA — runtime (répondeur).

Deux moteurs derrière la même interface :

  • HEURISTIQUE (P1, par défaut) — détecte l'intention, appelle les OUTILS du bus, et
    formule une réponse. Il ne « génère » pas de contenu libre : il ne peut donc pas
    INVENTER d'objet. C'est ce qui rend le POC honnête tant qu'aucun modèle n'est là.
  • llama.cpp (P0, quand un GGUF est chargé sur la MOCHAbin) — `llm_url` pointe un
    llama-server ; on l'utilise pour la FORMULATION, mais les objets viennent TOUJOURS
    des outils (le modèle n'est jamais une autorité).

Rend : { text, objects[], trace[], delegate|None }.
"""
from __future__ import annotations

import re
from typing import Any, Optional

import httpx

from . import vhost

# Vocabulaire minimal → type d'objet et service (français).
_TYPES = [
    (r"vid[ée]o|film|peertube", "media.video"),
    (r"audio|son|musique|radio|podcast|[ée]mission", "media.audio"),
    (r"document|fichier|\bdoc\b|note|pdf", "document"),
    (r"news|actu|sujet|article|topic", "news.topic"),
    (r"forum|discussion|\bfil\b|thread|bbs", "forum.thread"),
    (r"billet|post", "post"),
]
_SERVICES = ["waf", "peertube", "radio", "bbs", "nextcloud", "cloud", "podcaster",
             "metanews", "billets", "hall", "cspn", "wireguard"]


def _type_de(msg: str) -> str:
    for rx, t in _TYPES:
        if re.search(rx, msg):
            return t
    return ""


def _service_de(msg: str) -> str:
    for s in _SERVICES:
        if re.search(r"\b" + re.escape(s) + r"\b", msg):
            return "nextcloud" if s == "cloud" else s
    return ""


def _mots_cles(msg: str) -> str:
    # Mots vides + mots GÉNÉRIQUES (« sujets », « objets »…) qui ne sont pas des
    # critères de recherche mais une intention « liste-moi des choses ».
    stop = {"trouve", "cherche", "montre", "affiche", "liste", "moi", "la", "le", "les",
            "un", "une", "des", "du", "de", "sur", "dans", "quelle", "quel", "est",
            "derniere", "dernier", "dernieres", "derniers", "recente", "recent",
            "recents", "recentes", "récent", "récents", "récente", "récentes",
            "et", "à", "a", "pour", "avec", "me", "je", "tu", "peux", "qui", "quoi",
            "ce", "cette", "nouveau", "nouveaux", "nouveaute", "nouveautes", "neuf",
            # génériques d'objets
            "sujet", "sujets", "objet", "objets", "truc", "trucs", "chose", "choses",
            "news", "actu", "actus", "actualite", "actualites", "video", "vidéo",
            "videos", "vidéos", "audio", "podcast", "podcasts", "document", "documents",
            "fichier", "fichiers"}
    mots = [m for m in re.split(r"\W+", msg) if len(m) > 1 and m not in stop]
    return " ".join(mots)


async def _llm_text(cfg: dict, prompt: str) -> Optional[str]:
    """Formulation par llama-server si disponible — sinon None (repli heuristique).

    On passe par l'endpoint OpenAI-compat `/v1/chat/completions` : il applique le
    GABARIT DE CHAT du modèle (ChatML pour Qwen). Sans lui, `/completion` reçoit un
    prompt nu que le modèle instruct ne sait pas continuer (il rend un espace).
    """
    url = str(cfg.get("llm_url", "") or "").strip()
    if not url:
        return None
    try:
        async with httpx.AsyncClient(timeout=float(cfg.get("llm_timeout_s", 20))) as cli:
            r = await cli.post(url.rstrip("/") + "/v1/chat/completions",
                               json={"messages": [{"role": "user", "content": prompt}],
                                     "temperature": 0.3, "max_tokens": int(cfg.get("n_predict", 120))})
            if r.status_code == 200:
                j = r.json()
                txt = (((j.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
                return txt or None
    except Exception:
        return None
    return None


async def _intro(cfg: dict, titres: list, defaut: str) -> str:
    """Phrase d'intro FORMULÉE par le modèle (si présent) devant une liste d'objets.

    Élargit la « voix modèle » aux listes/délégations, pas seulement aux recherches.
    Les objets restent inchangés — le modèle n'habille que le texte.
    """
    if not cfg.get("llm_url") or not titres:
        return defaut
    g = await _llm_text(cfg, "Tu es ZIA, l'assistant local du Hall. En UNE phrase amicale et "
                             "courte (français), introduis ces résultats à l'utilisateur, sans "
                             "citer d'autre élément : " + " ; ".join(str(t) for t in titres[:5]))
    return g or defaut


async def respond(message: str, role: str, tools, cfg: dict, remote=None) -> dict:
    msg = (message or "").strip()
    low = msg.lower()
    trace: list[dict] = []
    engine = "llm" if cfg.get("llm_url") else "heuristique"

    # Salutation / capacités / remerciement — pas d'outil.
    if re.search(r"^\s*(salut|bonjour|hello|coucou|hey|yo)\b", low):
        return {"text": "Salut ! 🦊 Je connais ton Hall — tes médias, docs, contacts, "
                        "sujets. Demande-moi de trouver quelque chose, ou tape un mot-clé.",
                "objects": [], "trace": trace, "delegate": None, "engine": engine}
    if re.search(r"\bmerci\b", low):
        return {"text": "Avec plaisir. ❤", "objects": [], "trace": trace, "delegate": None, "engine": engine}
    if re.search(r"\b(aide|help|capacit|que sais-tu|tu peux quoi|comment ça marche)\b", low):
        return {"text": "Je cherche et j'ouvre les objets du Hall — sans jamais contourner "
                        "tes droits. Essaie : « trouve la dernière vidéo sur le WAF », "
                        "« montre les podcasts », « les sujets récents ». Pour un sujet "
                        "pointu, je passe la main à la ZIA du service concerné.",
                "objects": [], "trace": trace, "delegate": None, "engine": engine}

    # Question « explique/détaille » sur un service → délégation (niveau 2).
    service = _service_de(low)
    if service and re.search(r"\b(explique|détaille|detaille|pourquoi|en détail|en detail|approfond)\b", low):
        trace.append({"tool": "delegate", "args": {"service": service}})
        res = await tools.call("delegate", {"service": service,
                                            "reason": "question approfondie — RAG du service"}, role)
        deleg = res.get("result") if res.get("ok") else {"to": service, "reason": ""}
        # NIVEAU 2 (RAG VHOST) : la ZIA du service RÉPOND vraiment — RAG local sur son
        # histoire de développement (changelog déployé) + génération ancrée. On ramène
        # aussi les objets liés du bus (point d'entrée cliquable). Jamais d'invention.
        va = await vhost.answer(service, msg, cfg, _llm_text)
        trace.append({"tool": "search_objects", "args": {"query": service}})
        sres = await tools.call("search_objects", {"query": service}, role)
        objs = (sres.get("result") or [])[:4]
        if va.get("ok"):
            txt = f"🦝 **ZIA · {service}** — " + va["text"]
            eng = "llm" if (va.get("grounded") and cfg.get("llm_url")) else engine
            deleg = dict(deleg or {}, sources=va.get("sources", []))
        else:
            txt = (f"Je passe la main à **ZIA · {service}** 🦝 — mais je n'ai pas encore sa "
                   f"documentation locale à citer.")
            eng = engine
        return {"text": txt, "objects": objs, "trace": trace, "delegate": deleg, "engine": eng}

    # Sinon : RECHERCHE ou LISTE. On extrait type + mots-clés.
    type_ = _type_de(low)
    query = _mots_cles(low)
    recent = bool(re.search(r"récent|recent|dernier|derni[èe]re|nouveau|neuf|actualit", low))

    # « les sujets récents », « quoi de neuf », « montre les podcasts » (sans critère) :
    # on LISTE (par type si connu) plutôt que de chercher un mot littéral.
    if not query:
        if type_:
            trace.append({"tool": "search_objects", "args": {"query": "", "type": type_}})
            res = await tools.call("search_objects", {"query": "", "type": type_}, role)
            objs = res.get("result") or []
            quoi = {"media.video": "vidéos", "media.audio": "audio", "document": "documents",
                    "news.topic": "sujets", "forum.thread": "fils", "post": "billets"}.get(type_, "objets")
            txt = (f"Voici les **{len(objs)} {quoi}**" + (" les plus récents" if recent else "") + " :") if objs \
                else f"Aucun {quoi[:-1] if quoi.endswith('s') else quoi} visible pour toi."
            if objs:
                txt = await _intro(cfg, [o.get("title") for o in objs], txt)
            return {"text": txt, "objects": objs, "trace": trace, "delegate": None, "engine": engine}
        # Rien de précis : liste récente tous types.
        trace.append({"tool": "list_recent", "args": {"limit": 6}})
        res = await tools.call("list_recent", {"limit": 6}, role)
        objs = res.get("result") or []
        txt = f"Voici ce qui est récent — **{len(objs)} objets** :" if objs else "Rien à montrer pour l'instant."
        if objs:
            txt = await _intro(cfg, [o.get("title") for o in objs], txt)
        return {"text": txt, "objects": objs, "trace": trace, "delegate": None, "engine": engine}

    trace.append({"tool": "search_objects", "args": {"query": query, "type": type_}})
    res = await tools.call("search_objects", {"query": query, "type": type_}, role)
    objs = res.get("result") or []
    if objs:
        quoi = {"media.video": "vidéo(s)", "media.audio": "audio", "document": "document(s)",
                "news.topic": "sujet(s)", "forum.thread": "fil(s)"}.get(type_, "objet(s)")
        txt = f"J'ai trouvé **{len(objs)} {quoi}**" + (f" sur « {query} »" if query else "") + " :"
    else:
        # ESCALADE REMOTE (P5, niveau 3) — dernier recours, sous politique + budget.
        # Rien localement ? Si (et seulement si) le remote est autorisé et configuré,
        # on tente ; sinon on reste local, sans jamais bloquer.
        if remote is not None:
            trace.append({"tool": "delegate", "args": {"service": "remote"}})
            esc = await remote.escalate(msg, cfg, role)
            if esc and esc.get("text"):
                return {"text": esc["text"], "objects": [], "trace": trace,
                        "delegate": {"to": "remote", "reason": "escalade sous politique"},
                        "engine": "remote"}
        txt = ("Je n'ai rien trouvé de **visible** pour toi là-dessus. "
               "Essaie d'autres mots, ou demande « les sujets récents ».")
    # Formulation par le modèle (si présent), objets inchangés — même voix que les listes.
    if objs:
        txt = await _intro(cfg, [o.get("title") for o in objs], txt)
    return {"text": txt, "objects": objs, "trace": trace, "delegate": None, "engine": engine}
