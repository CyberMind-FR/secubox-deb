# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox_core.qdisc — un seul propriétaire du qdisc racine (#2050)
CyberMind — https://cybermind.fr

`qos` (HTB) et `traffic` (CAKE) posent chacun un qdisc « root » et commencent par
supprimer celui qui existe : le second défait le premier sans le savoir. Chaque
module déclare donc l'interface qu'il pilote ; l'autre s'en abstient.

Un fichier par interface dans SECUBOX_QDISC_DIR (défaut /var/lib/secubox/qdisc-owner),
créé de façon atomique (O_EXCL) : deux demandes simultanées n'ont qu'un gagnant.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

_NOM_IFACE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}$")


def _dossier() -> Path:
    return Path(os.environ.get("SECUBOX_QDISC_DIR", "/var/lib/secubox/qdisc-owner"))


def _fichier(iface: str) -> Path:
    if not _NOM_IFACE.match(iface or "") or iface in (".", ".."):
        raise ValueError(f"nom d'interface invalide : {iface!r}")
    return _dossier() / iface


def owner(iface: str) -> Optional[str]:
    """Le module qui pilote le qdisc racine de `iface`, ou None."""
    try:
        return _fichier(iface).read_text().strip() or None
    except FileNotFoundError:
        return None


def claim(iface: str, module: str) -> bool:
    """Réclame `iface` ; False si un AUTRE module la pilote déjà."""
    f = _fichier(iface)
    f.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        return owner(iface) == module
    with os.fdopen(fd, "w") as h:
        h.write(module + "\n")
    return True


def release(iface: str, module: str) -> None:
    """Libère `iface`, seulement si `module` en est le propriétaire."""
    if owner(iface) == module:
        _fichier(iface).unlink(missing_ok=True)
