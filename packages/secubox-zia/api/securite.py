# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox ZIA :: expliquer les blocages du WAF (#3583)

Le CODE établit les faits (comptes, catégories, gravité, dernière requête) à partir de l'API du WAF ; le modèle ne
fait que les traduire en français et PROPOSER une action, marquée « à valider ». Il n'est jamais une autorité :
rien n'est appliqué, et les faits sont rendus à côté de l'explication pour que l'administrateur vérifie.
Le WAF est lu avec le jeton de l'administrateur qui demande (ses droits, pas ceux de ZIA).
"""
from typing import Any, Optional

import httpx

CHAMPS_ALERTE = ("method", "host", "path", "user_agent", "rule_id", "tool", "category", "severity", "action")


async def blocages(cfg: dict, jeton: str, limite: int = 15) -> Optional[list[dict]]:
    """Les adresses bloquées récentes, agrégées par le WAF ; None si le WAF refuse ou ne répond pas."""
    sock = cfg.get("waf_sock", "/run/secubox/waf.sock")
    try:
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=sock), timeout=8.0) as cli:
            r = await cli.get("http://x/alerts", params={"limit": max(1, min(int(limite), 30)), "aggregate": "true"},
                              headers={"Accept": "application/json", "Authorization": f"Bearer {jeton}"})
        if r.status_code != 200:
            return None
        return [a for a in (r.json().get("alerts") or []) if isinstance(a, dict) and a.get("client_ip")]
    except (httpx.HTTPError, ValueError):
        return None


def faits(entree: dict) -> dict[str, Any]:
    """Fiche factuelle d'une adresse bloquée : seulement ce que le WAF a mesuré, rien d'interprété."""
    derniere = entree.get("latest_alert") or {}
    return {
        "adresse": entree.get("client_ip"),
        "pays": entree.get("country") or "inconnu",
        "alertes": entree.get("count"),
        "categories": sorted(entree.get("categories") or []),
        "gravite_max": entree.get("max_severity"),
        "premiere": entree.get("first_seen"),
        "derniere_vue": entree.get("last_seen"),
        "deja_bannie": bool(entree.get("currently_banned")),
        "derniere_requete": {k: str(derniere.get(k))[:200] for k in CHAMPS_ALERTE if derniere.get(k)},
    }


def consigne(f: dict) -> str:
    """La demande au modèle : traduire les faits, ne rien ajouter, proposer sans décider."""
    lignes = "\n".join(f"- {k} : {v}" for k, v in f.items())
    return (
        "Tu aides l'administrateur d'une box de sécurité SecuBox. Voici les FAITS mesurés par son pare-feu "
        "applicatif (WAF) pour une adresse bloquée :\n" + lignes + "\n\n"
        "En français simple, en 4 à 6 phrases : 1) explique ce que cette adresse a probablement tenté, d'après la "
        "requête et les catégories ; 2) dis si c'est grave pour un particulier ; 3) termine par UNE proposition "
        "d'action commençant par « Proposition (à valider) : ». N'invente aucun fait absent de la liste ; si un "
        "élément manque, dis que tu ne le sais pas. Ne prétends jamais avoir agi."
    )
