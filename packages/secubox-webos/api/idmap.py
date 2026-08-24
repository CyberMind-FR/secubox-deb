# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — jointure id↔domaine du registre normalisé (P1)."""
from typing import Optional, Tuple


def resolve(item: dict, suffix: str = ".gk2.secubox.in") -> Tuple[Optional[str], bool]:
    """Resolve the (domain, same_origin) pair for a menu/registry item.

    - ``same_origin`` truthy ⇒ ``(None, True)`` : servi depuis le même
      domaine que le Hub, aucune résolution de domaine nécessaire.
    - ``domain`` explicite ⇒ ``(domain, False)``.
    - Sinon, repli gracieux par convention ⇒ ``(f"{id}{suffix}", False)``.
    """
    if item.get("same_origin"):
        return (None, True)
    dom = item.get("domain")
    if dom:
        return (dom, False)
    return (f"{item['id']}{suffix}", False)
