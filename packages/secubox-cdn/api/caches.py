# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Caches réels de la box (#2467) : taille, fichiers et âge de chaque dossier de /var/cache/secubox, en lecture seule.

Le dossier géré jusqu'ici par ce module (/var/cache/secubox-cdn) n'existait pas : la page ne montrait que du vide. Un cache dont le dossier est fermé au compte
du service (polices, Toolbox…) rend `lisible: false` et des mesures `null` — jamais un zéro trompeur. Aucun lien symbolique n'est suivi ; le parcours est borné
(fichiers et durée) et un parcours interrompu est dit (`partiel: true`)."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

RACINE = Path("/var/cache/secubox")
MAX_FICHIERS = 200_000
BUDGET_S = 3.0


def mesurer(dossier: Path, maintenant: Optional[float] = None, max_fichiers: int = MAX_FICHIERS, budget_s: float = BUDGET_S) -> dict:
    """{octets, fichiers, recent, lisible, partiel} d'un dossier ; `recent` = modification la plus récente (epoch) ou None."""
    debut = time.monotonic()
    octets = fichiers = 0
    recent: Optional[float] = None
    lisible, partiel = True, False
    pile = [str(dossier)]
    while pile:
        d = pile.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            pile.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            octets += st.st_size
                            fichiers += 1
                            recent = st.st_mtime if recent is None or st.st_mtime > recent else recent
                    except OSError:
                        continue
                    if fichiers >= max_fichiers or time.monotonic() - debut > budget_s:
                        return {"octets": octets, "fichiers": fichiers, "recent": recent, "lisible": lisible, "partiel": True}
        except PermissionError:
            if d == str(dossier):
                return {"octets": None, "fichiers": None, "recent": None, "lisible": False, "partiel": False}
            lisible, partiel = lisible, True          # un sous-dossier fermé : la mesure est celle de ce qui est lisible, et le dit
        except OSError:
            partiel = True
    return {"octets": octets, "fichiers": fichiers, "recent": recent, "lisible": lisible, "partiel": partiel}


def lister(racine: Path = RACINE, **k) -> dict:
    """Un enregistrement par dossier ou fichier de cache directement sous `racine`, du plus gros au plus petit (illisibles en dernier)."""
    caches = []
    try:
        entrees = sorted(racine.iterdir())
    except OSError:
        return {"disponible": False, "caches": [], "octets_total": None, "illisibles": None}
    for p in entrees:
        try:
            if p.is_symlink():
                continue
            if p.is_dir():
                m = mesurer(p, **k)
                caches.append({"nom": p.name, "type": "dossier", **m})
            elif p.is_file():
                st = p.stat()
                caches.append({"nom": p.name, "type": "fichier", "octets": st.st_size, "fichiers": 1, "recent": st.st_mtime, "lisible": True, "partiel": False})
        except OSError:
            caches.append({"nom": p.name, "type": "dossier", "octets": None, "fichiers": None, "recent": None, "lisible": False, "partiel": False})
    caches.sort(key=lambda c: (c["octets"] is None, -(c["octets"] or 0), c["nom"]))
    lisibles = [c for c in caches if c["octets"] is not None]
    return {"disponible": True, "caches": caches, "octets_total": sum(c["octets"] for c in lisibles) if lisibles else None,
            "illisibles": sum(1 for c in caches if not c["lisible"])}
