# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Contrôles anti-invention SANS modèle, partagés par le résumé des menaces (api/menaces.py, #3583) et l'analyste de
la veille (veille/analyste.py, #3722) : un seul code, pas de copie.

`anomalies(texte, releve)` rend les constats (liste vide = rien à redire) : chiffres absents du relevé (arrondi toléré),
pourcentages qui ne sont pas des parts du relevé, tendance ou nouveauté affirmée sans mesure, pays absents. Le relevé
est un dict quelconque ; ses clés commençant par « _ » sont internes et ignorées. Module pur : ni FastAPI, ni réseau.
"""
import json
import re

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PAYS_NOMS = {"CN": r"chin", "US": r"usa|[ée]tats[- ]unis|am[ée]ric", "RU": r"russ", "DE": r"allemagne|allemand",
             "FR": r"france|fran[çc]ais", "BR": r"br[ée]sil", "KR": r"cor[ée]e", "IN": r"inde\b|indien",
             "NL": r"pays[- ]bas|n[ée]erlandais", "GB": r"royaume[- ]uni|britanni", "HK": r"hong[- ]kong",
             "SG": r"singapour", "VN": r"vi[eê]t", "IR": r"\biran", "UA": r"ukrain", "JP": r"japon", "TW": r"ta[ïi]wan"}
TENDANCE = re.compile(
    r"hausse|baisse|augment|diminu|recul|progress|explos|en forte|r[ée]cemment|nouve(?:au|lle|aux)s?\b|r[ée]cent", re.I)


def visible(r: dict) -> dict:
    """Le relevé sans ses clés internes (`_bannies`…)."""
    return {k: v for k, v in r.items() if not str(k).startswith("_")}


def anomalies(texte: str, releve: dict) -> list:
    """Constats du contrôle SANS modèle ; le reste n'est pas prouvé."""
    nombres = set(re.findall(r"\d+(?:[.,]\d+)?", json.dumps(visible(releve), ensure_ascii=False, default=str)))
    propre = IPV4.sub(" ", re.sub(r"`[^`]*`|\b[0-9a-f]{12,64}\b|\b\d+(?:\.\d+){1,3}/\d+\b", " ", texte))
    valeurs = [float(v.replace(",", ".")) for v in nombres]

    def connu(n):   # un arrondi (91,9 → 92) n'est pas une invention
        x = float(n.replace(",", "."))
        return any(abs(x - v) <= 0.5 for v in valeurs)
    absents = sorted({n for n in re.findall(r"\b\d+(?:[.,]\d+)?\b", propre)
                      if len(n.replace(",", "").replace(".", "")) >= 2 and not connu(n)})
    notes = []
    if absents:
        notes.append("chiffres absents du relevé : " + ", ".join(absents[:8]))
    # Un nombre suivi de « % » doit être une PART du relevé (clés en pct / part*), pas un compte : « +60 % » pour
    # « sasl_failed +60 » (60 alertes de plus) est une invention d'unité (vu le 14/11/2026).
    parts: list[float] = []

    def _parts(x, part=False):   # `part` : une clé ancêtre en pct / part* (les sous-clés sont des catégories)
        if isinstance(x, dict):
            for k, v in x.items():
                _parts(v, part or "pct" in str(k) or str(k).startswith("part"))
        elif isinstance(x, list):
            for v in x:
                _parts(v, part)
        elif part and isinstance(x, (int, float)) and not isinstance(x, bool):
            parts.append(float(x))
    _parts(visible(releve))
    faux_pct = sorted({m.group(1) for m in re.finditer(r"(\d+(?:[.,]\d+)?)\s*%", propre)
                       if not any(abs(float(m.group(1).replace(",", ".")) - v) <= 0.5 for v in parts)},
                      key=lambda n: float(n.replace(",", ".")))
    if faux_pct:
        notes.append("pourcentages absents du relevé (des comptes donnés pour des parts ?) : "
                     + ", ".join(f + " %" for f in faux_pct[:8]))
    if not (releve.get("evolution_1h") or {}).get("disponible") and TENDANCE.search(texte):
        notes.append("tendance ou nouveauté affirmée sans mesure : "
                     + (releve.get("evolution_1h") or {}).get("raison", "pas de recul"))
    codes = {str(x).split()[0] for x in releve.get("pays") or [] if str(x).split()} | set(releve.get("bans_par_pays") or {})
    cites = [c for c, motif in PAYS_NOMS.items() if re.search(motif, texte, re.I) and c not in codes]
    if cites:
        notes.append("pays absents du relevé : " + ", ".join(cites))
    return notes
