# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Listes brutes (`<source>.lst`) et dédoublonnage des zones : un sous-domaine d'une entrée déjà listée est couvert par la zone de son parent."""
import re
from pathlib import Path
from typing import Iterable

from . import domaines

_CAT = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
MAX_LST_OCTETS = 100_000_000                       # un fichier plus gros est ignoré (écrit par un compte non root, lu par root)


def dedoublonner(noms: Iterable) -> list:
    uniques = sorted(set(noms), key=lambda n: (n.count("."), n))        # les parents d'abord
    gardes, vus = [], set()
    for n in uniques:
        e = n.split(".")
        if any(".".join(e[k:]) in vus for k in range(1, len(e) - 1)):
            continue
        vus.add(n)
        gardes.append(n)
    return sorted(gardes)


def charger(dossier, cat: str) -> list:
    """Union dédoublonnée des listes brutes d'une catégorie ; chaque ligne est REVALIDÉE (le fichier n'est jamais cru sur parole)."""
    if not isinstance(cat, str) or not _CAT.match(cat):
        return []
    rep = Path(dossier) / cat
    noms = []
    if rep.is_dir():
        for f in sorted(rep.glob("*.lst")):
            if f.is_symlink() or not f.is_file() or f.stat().st_size > MAX_LST_OCTETS:
                continue
            for ligne in f.read_text(encoding="utf-8", errors="replace").splitlines():
                n = domaines.valider(ligne)
                if n:
                    noms.append(n)
    return dedoublonner(noms)
