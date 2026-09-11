# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""core.crypto.hermes — ré-export de compatibilité.

L'implémentation souveraine vit désormais dans ``secubox_core.crypto.hermes``
(installée par le paquet ``secubox-core``, importable au runtime). Ce module
racine, non packagé, n'est qu'un alias historique : il ré-exporte l'API réelle
pour que ``import core.crypto`` cesse d'échouer quand ``secubox_core`` est
présent (dev-tree / board).
"""

from secubox_core.crypto.hermes import (  # noqa: F401
    Identity,
    Session,
    derive_key_material,
)

__all__ = ["Identity", "Session", "derive_key_material"]
