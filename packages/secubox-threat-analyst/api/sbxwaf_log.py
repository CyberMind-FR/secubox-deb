# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Lecture de /var/log/secubox/waf/waf-threats.log tel que sbxwaf l'écrit.

Une ligne JSON par événement : timestamp, client_ip, host, method, path,
category, severity, rule_id, action (detect | warning | banned | robot),
user_agent, et selon les cas tool, leurre, http_fingerprint.

L'ancien collecteur ne retenait que les lignes portant `blocked: true`, un champ
que sbxwaf n'émet plus : le panneau restait vide depuis le remplacement de
l'ancien WAF. Ce module n'a aucun effet de bord à l'import, pour être testable.
"""
import hashlib
import json
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

# action sbxwaf -> gravité. « robot » est un passage de robot connu : pas une menace.
_GRAVITE_PAR_ACTION = {"banned": "high", "blocked": "high", "warning": "medium", "detect": None}
_GRAVITES = {"critical", "high", "medium", "low"}
_UA_MAX = 160


def _gravite(data: Dict[str, Any]) -> Optional[str]:
    action = data.get("action")
    if action not in _GRAVITE_PAR_ACTION:
        return None
    fixe = _GRAVITE_PAR_ACTION[action]
    if fixe:
        return fixe
    declaree = data.get("severity")
    return declaree if declaree in _GRAVITES else "low"


def alerte_depuis_ligne(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Une ligne du journal -> une alerte (champs de ThreatAlert), ou None."""
    gravite = _gravite(data)
    if gravite is None:
        return None
    cle = "|".join(str(data.get(k, "")) for k in ("timestamp", "client_ip", "host", "path", "rule_id", "action"))
    details = {k: data[k] for k in ("host", "method", "path", "rule_id", "action", "tool", "leurre", "http_fingerprint") if k in data}
    if data.get("user_agent"):
        details["user_agent"] = str(data["user_agent"])[:_UA_MAX]
    return {
        "id": "waf-" + hashlib.sha1(cle.encode()).hexdigest()[:16],
        "source": "waf",
        "severity": gravite,
        "type": data.get("category") or "unknown",
        "ip": data.get("client_ip"),
        "details": details,
        "timestamp": data.get("timestamp", ""),
    }


def _lignes_json(lignes: Iterable[str]) -> Iterable[Dict[str, Any]]:
    for ligne in lignes:
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            data = json.loads(ligne)
        except ValueError:
            continue
        if isinstance(data, dict):
            yield data


def alertes_depuis_lignes(lignes: Iterable[str]) -> List[Dict[str, Any]]:
    return [a for a in map(alerte_depuis_ligne, _lignes_json(lignes)) if a]


def vue_d_ensemble(lignes: Iterable[str], aujourd_hui: str) -> Dict[str, Any]:
    """Compteurs du panneau, calculés sur les lignes fournies (dernières lignes du journal)."""
    total = jour = bannis = 0
    categories: Counter = Counter()
    gravites: Counter = Counter()
    regles = set()
    vhosts: Counter = Counter()
    for data in _lignes_json(lignes):
        total += 1
        if str(data.get("timestamp", "")).startswith(aujourd_hui):
            jour += 1
        if data.get("action") in ("banned", "blocked"):
            bannis += 1
        if data.get("rule_id"):
            regles.add(data["rule_id"])
        categories[data.get("category") or "unknown"] += 1
        gravites[_gravite(data) or "info"] += 1
        if data.get("host"):
            vhosts[data["host"]] += 1
    return {
        "running": True,
        "threats_today": jour,
        "threats_total": total,
        "blocked_24h": bannis,
        "rules_loaded": len(regles),
        "by_category": dict(categories.most_common(12)),
        "by_severity": dict(gravites),
        "top_countries": [],
        "top_vhosts": [{"name": h, "count": n} for h, n in vhosts.most_common(5)],
    }


def synthese_locale(alertes: List[Dict[str, Any]]) -> str:
    """Résumé lisible sans modèle de langage : ce qui revient le plus, et qui."""
    if not alertes:
        return "Aucune alerte à analyser."
    types = Counter(a.get("type") or "unknown" for a in alertes)
    ips = Counter(a.get("ip") for a in alertes if a.get("ip"))
    gravites = Counter(a.get("severity") for a in alertes)
    lignes = [f"{len(alertes)} alerte(s) analysée(s) localement (modèle de langage indisponible)."]
    lignes.append("Gravité : " + ", ".join(f"{g} {n}" for g, n in gravites.most_common()) + ".")
    lignes.append("Types les plus fréquents : " + ", ".join(f"{t} ({n})" for t, n in types.most_common(5)) + ".")
    if ips:
        lignes.append("Adresses les plus actives : " + ", ".join(f"{i} ({n})" for i, n in ips.most_common(5)) + ".")
    bannies = [a for a in alertes if (a.get("details") or {}).get("action") == "banned"]
    if bannies:
        lignes.append(f"{len(bannies)} bannissement(s) déjà appliqué(s) par le WAF.")
    return "\n".join(lignes)
