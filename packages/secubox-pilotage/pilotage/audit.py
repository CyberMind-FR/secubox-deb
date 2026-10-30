# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: journal d'audit append-only (#3126)

Une ligne JSON par décision, ajoutée à `/var/log/secubox/audit.log` (O_APPEND, jamais réécrite). Les champs sont bornés et ne portent
jamais de valeur lue sur une box. Synchrone : à appeler par asyncio.to_thread. Lève OSError si la ligne ne peut pas être écrite.
Le journal n'est JAMAIS créé ni tronqué ici (ouverture sans création ni troncature : l'ajout seul est tenu par ce code) : secubox-core et le postinst le
garantissent ; absent, l'audit échoue franchement et l'action est refusée. Le profil AppArmor accorde `w` et non `a` (banc gk2, #3126) :
avec `a` seul, l'ouverture O_WRONLY|O_APPEND passe (médiée en ajout) mais chaque write() est revérifié en MAY_WRITE et refusé (EACCES).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable

AUDIT_DEFAUT = Path("/var/log/secubox/audit.log")
_RESERVES = ("ts", "module", "action")


def journal(chemin: Path = AUDIT_DEFAUT) -> Callable[[str, dict], None]:
    chemin = Path(chemin)

    def audit(evenement: str, champs: dict) -> None:
        ligne = {k: (v if isinstance(v, (int, bool)) or v is None else str(v)[:300]) for k, v in champs.items() if k not in _RESERVES}
        ligne.update(ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), module="pilotage", action=evenement)
        octets = (json.dumps(ligne, ensure_ascii=False) + "\n").encode("utf-8")
        fd = os.open(chemin, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.write(fd, octets)
        finally:
            os.close(fd)

    return audit
