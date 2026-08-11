# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm.backend — déclaration d'un fournisseur + registry.

Un `Backend` regroupe tout ce qui varie entre claude.ai, chatgpt.com et
gemini.google.com : URL, sélecteurs, mode de soumission du prompt. C'est la
seule couche qui connaît ces détails — `session.py` ne manipule jamais une
constante spécifique à un fournisseur.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

__all__ = [
    "Selectors",
    "Backend",
    "register",
    "get_backend",
    "available_backends",
]


@dataclass(frozen=True)
class Selectors:
    """Sélecteurs CSS/ARIA utilisés pour piloter l'interface d'un fournisseur.

    Fragiles par nature : un changement de front-end côté fournisseur les
    casse sans préavis, sans lien avec ce dépôt. Voir README § Corriger un
    sélecteur cassé pour la procédure de mise à jour.
    """

    composer: str
    send_button: str
    stop_button: str
    assistant_message: str
    login_indicator: str


@dataclass(frozen=True)
class Backend:
    """Déclaration complète d'un fournisseur de chat web piloté par webllm.

    Pas de champ « submit_mode » : `session.py` tente toujours le bouton
    d'envoi et se rabat automatiquement sur la touche Entrée s'il est
    indisponible (voir `WebLLMSession._trigger_send`) — comportement éprouvé
    de l'implémentation d'origine, valable pour tout fournisseur.
    """

    name: str
    url: str
    selectors: Selectors
    line_break_key: str = "Shift+Enter"  # saut de ligne dans le composer sans envoyer


_REGISTRY: dict[str, Backend] = {}


def register(factory: Callable[[], Backend]) -> Callable[[], Backend]:
    """Décorateur : construit et enregistre le backend renvoyé par `factory`.

    Usage dans un module de `backends/` — c'est la totalité de ce qu'un
    nouveau fournisseur doit écrire, sans toucher au reste du package :

        @register
        def _backend() -> Backend:
            return Backend(name="exemple", url="https://...", selectors=...)
    """
    backend = factory()
    if backend.name in _REGISTRY:
        raise ValueError(f"backend déjà enregistré : {backend.name!r}")
    _REGISTRY[backend.name] = backend
    return factory


def get_backend(name: str) -> Backend:
    """Résout un backend par nom ; erreur explicite (pas de KeyError nu) si inconnu."""
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(available_backends()) or "(aucun)"
        raise KeyError(f"backend inconnu : {name!r} — disponibles : {known}") from None


def available_backends() -> list[str]:
    """Liste triée des noms de backends actuellement enregistrés."""
    return sorted(_REGISTRY)
