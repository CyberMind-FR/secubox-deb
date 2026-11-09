# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lecture bornée des caches d'autres modules, avec leur fraîcheur.

Un cache se lit sans suivre de lien, fichier ordinaire, 8 Mio au plus. Sa fraîcheur vient de l'horodatage qu'il
porte lui-même (jamais de la date du fichier seule : un fichier réécrit sans nouvelle mesure resterait « frais »).
États : `fresh`, `stale` (trop vieux), `absent`, `invalid` (illisible, trop gros, mal formé, horodatage futur).
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

TAILLE_MAX = 8 * 1024 * 1024
TOLERANCE_FUTUR_S = 120


@dataclass
class Lecture:
    etat: str
    donnees: Any = None
    age_s: Optional[float] = None
    motif: str = ""


def lire_json_borne(chemin: Path, taille_max: int = TAILLE_MAX) -> Any:
    """JSON d'un fichier ordinaire, ouvert sans suivre de lien ; lève OSError/ValueError sinon."""
    fd = os.open(str(chemin), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("pas un fichier ordinaire")
        if st.st_size > taille_max:
            raise ValueError(f"trop gros ({st.st_size} octets)")
        morceaux, reste = [], taille_max + 1
        while reste > 0:
            m = os.read(fd, min(reste, 1 << 16))
            if not m:
                break
            morceaux.append(m)
            reste -= len(m)
        brut = b"".join(morceaux)
        if len(brut) > taille_max:
            raise ValueError("trop gros")
        return json.loads(brut.decode("utf-8"))
    finally:
        os.close(fd)


def instant(valeur: Any) -> Optional[datetime]:
    """Horodatage RFC 3339 (ou epoch) → datetime UTC ; None si absent ou mal formé."""
    if isinstance(valeur, bool):
        return None
    if isinstance(valeur, (int, float)):
        try:
            return datetime.fromtimestamp(float(valeur), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(valeur, str) and valeur:
        try:
            d = datetime.fromisoformat(valeur.replace("Z", "+00:00"))
        except ValueError:
            return None
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return None


def lire_source(chemin: Path, horodatage: Callable[[Any], Any], perime_apres_s: float,
                maintenant: Optional[datetime] = None) -> Lecture:
    maintenant = maintenant or datetime.now(timezone.utc)
    try:
        donnees = lire_json_borne(chemin)
    except FileNotFoundError:
        return Lecture("absent", motif="fichier absent")
    except PermissionError:
        return Lecture("invalid", motif="lecture refusée")
    except RecursionError:
        return Lecture("invalid", motif="JSON trop imbriqué")
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return Lecture("invalid", motif=str(e)[:120])
    if not isinstance(donnees, dict):
        return Lecture("invalid", motif="forme inattendue")
    quand = instant(horodatage(donnees))
    if quand is None:
        return Lecture("invalid", donnees, motif="horodatage absent")
    age = (maintenant - quand).total_seconds()
    if age < -TOLERANCE_FUTUR_S:
        return Lecture("invalid", donnees, age, "horodatage dans le futur")
    if age > perime_apres_s:
        return Lecture("stale", donnees, age, f"relevé vieux de {int(age)} s")
    return Lecture("fresh", donnees, max(age, 0.0))
