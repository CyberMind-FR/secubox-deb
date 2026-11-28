# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Consigne du dialogue (#4058, Task 7) : gabarit en sept parties + faits nouveaux + règles impératives."""
from __future__ import annotations

from typing import Any, Dict, List

REGLES = (
    "Règles impératives :",
    "- N'utilise QUE les faits et chiffres donnés ci-dessous ; n'invente aucun nombre, aucune date, aucun nom.",
    "- N'attribue jamais une activité à un hébergeur ou à un opérateur réseau : ils hébergent des adresses, ils "
    "n'agissent pas.",
    "- Ne prétends à aucune opération d'État, aucun financement, aucune coordination.",
    "- Distingue les bannissements (adresses bloquées par le pare-feu), les attaques réussies et les incidents : "
    "un ban n'est ni une attaque réussie ni un incident.",
    "- Aucune adresse IP, aucun nom de machine interne, aucun détail de configuration.",
    "- Pas de ton publicitaire, pas d'éloge de SecuBox.",
    "- Une supposition se dit comme telle (« peut-être », « il semble »).",
)
FORMAT = ("Format : un dialogue entre deux voix, une réplique par ligne, chaque ligne commençant par « V1: » ou "
          "« V2: », sans autre texte. Répliques courtes (une à trois phrases).")


def consigne(sujets: List[Dict[str, Any]], faits: List[Dict[str, Any]], gabarit: str) -> str:
    plan = "\n".join(ln for ln in gabarit.splitlines() if not ln.lstrip().startswith("#")).strip()
    noms = ", ".join(f"{s.get('nom') or s.get('id')} ({s.get('genre', 'sujet')})" for s in sujets) or "aucun"
    lignes = [f"- {'[marquant] ' if f.get('marquant') else ''}{f.get('texte', '')}" for f in faits]
    return "\n\n".join([
        "Tu écris une émission de décryptage à deux voix sur l'activité observée par le pare-feu.",
        "Sujets : " + noms,
        "Faits nouveaux :\n" + ("\n".join(lignes) or "- aucun"),
        plan, "\n".join(REGLES), FORMAT])
