# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm.backends — import de ce paquet = enregistrement de tous
les backends présents dans ce répertoire.

Découverte automatique par `pkgutil` : ajouter un fournisseur se résume à un
nouveau fichier ici portant un `@register` sur sa fonction `_backend()` — ce
fichier `__init__.py` n'a lui-même jamais besoin d'être modifié.
"""

from __future__ import annotations

import importlib
import pkgutil

__all__: list[str] = []

for _module_info in pkgutil.iter_modules(__path__, prefix=f"{__name__}."):
    importlib.import_module(_module_info.name)
del _module_info
