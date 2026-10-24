# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Ancre du maître (#3100) : la box garde l'identité du maître qui l'a flashée.

Les étapes suivantes (jonction du maillage, rattrapage, push du premier pas) refusent tout autre maître que celui de l'ancre. Sans ancre, tout maître est accepté
(box vierge). `adresse` est l'hôte IPv4 de jonction du maître, sans port. Rien de secret ici : la clé est publique ; l'audit refuse tout code ou jeton."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from typing import Optional

CHEMIN = "/etc/secubox/p2p/ancre-maitre.json"
_INTERDITS = ("code", "jeton", "token")


def empreinte(cle_publique: str) -> str:
    """16 premiers caractères hexadécimaux du SHA-256 de la clé publique (UTF-8)."""
    return hashlib.sha256(cle_publique.encode("utf-8")).hexdigest()[:16]


def lire(chemin: str = CHEMIN) -> Optional[dict]:
    """L'ancre, ou None si le fichier est absent ou illisible."""
    try:
        with open(chemin, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def ecrire(cle_publique: str, adresse: str, nom: str, empreinte: str,
           chemin: str = CHEMIN, ecraser: bool = False) -> bool:
    """Pose l'ancre (atomique, 0644). False, sans rien écrire, si elle existe et que `ecraser` est faux."""
    if os.path.exists(chemin) and not ecraser:
        return False
    dossier = os.path.dirname(chemin) or "."
    os.makedirs(dossier, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dossier, prefix=".ancre-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"cle_publique": cle_publique, "adresse": adresse, "nom": nom,
                       "empreinte": empreinte}, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def accepte(ancre: Optional[dict], cle_maitre: str) -> bool:
    """Vrai sans ancre, ou si la clé du maître est celle de l'ancre."""
    return ancre is None or ancre.get("cle_publique") == cle_maitre


def audit(evenement: str, chemin: str = "/var/log/secubox/audit.log", **champs) -> None:
    """Ajoute une ligne JSON à l'audit. ValueError si un champ porte un code ou un jeton."""
    if any(k in _INTERDITS for k in champs):
        raise ValueError("l'audit ne reçoit ni code ni jeton")
    ligne = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "module": "p2p", "evenement": evenement, **champs}
    with open(chemin, "a", encoding="utf-8") as f:
        f.write(json.dumps(ligne, ensure_ascii=False) + "\n")
