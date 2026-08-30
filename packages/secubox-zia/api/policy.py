# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ZIA — politique / ACL (hors modèle).

Le LLM n'est JAMAIS une autorité. La visibilité d'un objet est filtrée ICI, à froid,
avant qu'il ne soit rendu — le modèle ne voit que ce que le rôle du demandeur autorise.
Le remote est soumis à une politique explicite (désactivé par défaut).
"""
from __future__ import annotations

# Échelle de rôles : un rôle « voit » sa visibilité et toutes celles au-dessous.
_ORDRE = {"guest": 0, "registered": 1, "member": 2, "admin": 3}


def rang(role: str) -> int:
    return _ORDRE.get((role or "guest").strip().lower(), 0)


def visible(obj: dict, role: str) -> bool:
    """L'objet est-il visible pour ce rôle ?

    `visibility` liste les rôles admis (« guest|registered|member|admin ») OU un seul
    rôle-plancher. On admet si le demandeur atteint le plus BAS des rôles cités.
    """
    vis = str(obj.get("visibility", "guest"))
    roles = [r.strip() for r in vis.replace(",", "|").split("|") if r.strip()]
    if not roles:
        return True
    plancher = min(rang(r) for r in roles)
    return rang(role) >= plancher


def filtre(objets: list, role: str) -> list:
    """Ne garde que les objets visibles — c'est le cœur de l'ACL côté bus."""
    return [o for o in objets if visible(o, role)]


def remote_autorise(cfg: dict, role: str) -> bool:
    """Le remote (niveau 3) est désactivé par défaut ; activable par politique."""
    if not cfg.get("remote_enabled", False):
        return False
    mini = cfg.get("remote_role_min", "admin")
    return rang(role) >= rang(mini)
