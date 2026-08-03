# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm — automatisation locale d'une session de chat web,
multi-fournisseur, sous contrôle direct de l'opérateur.

Invariant : la session vit dans un profil de navigateur persistant local.
Aucun cookie de session n'est jamais extrait ni rejoué ; aucun port ni
endpoint HTTP n'est ouvert par ce package ; aucun accès mutualisé entre
utilisateurs. Mono-utilisateur, exécution locale uniquement.
"""

from __future__ import annotations

# Importer ce sous-paquet déclenche l'enregistrement de claude/gpt/gemini.
from webllm import backends  # noqa: F401
from webllm.backend import (
    Backend,
    Selectors,
    available_backends,
    get_backend,
    register,
)
from webllm.session import (
    Config,
    EmptyResponseError,
    SessionNotReadyError,
    WebLLMSession,
)

__all__ = [
    "Backend",
    "Selectors",
    "register",
    "get_backend",
    "available_backends",
    "Config",
    "WebLLMSession",
    "SessionNotReadyError",
    "EmptyResponseError",
]
