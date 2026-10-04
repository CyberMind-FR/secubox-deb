# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Listes brutes (`<source>.lst`) et dédoublonnage des zones : un sous-domaine d'une entrée déjà listée est couvert par la zone de son parent."""
import os
import re
import stat
from pathlib import Path
from typing import Iterable

from . import domaines
from .etatsur import ErreurEtat

_CAT = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_SOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
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


def _lire_liste(fd_cat: int, nom: str, budget):
    """Octets d'une liste brute, lue RELATIVEMENT au dossier de la catégorie déjà ouvert : lien, fichier non régulier ou trop gros → ignoré."""
    try:
        f = os.open(nom, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd_cat)
    except OSError:
        return None
    try:
        st = os.fstat(f)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_LST_OCTETS:
            return None
        budget.prendre(st.st_size)
        morceaux, reste = [], st.st_size
        while reste > 0:
            m = os.read(f, min(reste, 1 << 20))
            if not m:
                break
            morceaux.append(m)
            reste -= len(m)
        return b"".join(morceaux)
    finally:
        os.close(f)


def charger_sur(etat, cat: str, sources, budget) -> list:
    """Union dédoublonnée des listes brutes des SEULES sources du catalogue (`sources` : leurs noms), d'après un `EtatSur` : `listes/` et `listes/<cat>/`
    sont ouverts sans suivre de lien (ErreurEtat s'il y en a un), chaque fichier relativement à son dossier, chaque ligne revalidée."""
    if not isinstance(cat, str) or not _CAT.match(cat):
        return []
    try:
        fd_listes = etat.sous_dossier("listes")
    except FileNotFoundError:
        return []
    try:
        try:
            fd_cat = os.open(cat, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd_listes)
        except FileNotFoundError:
            return []
        except OSError:
            raise ErreurEtat(f"listes/{cat} : lien symbolique ou dossier invalide") from None
        try:
            noms = []
            for s in sources:
                if not isinstance(s, str) or not _SOURCE.match(s):
                    continue
                brut = _lire_liste(fd_cat, s + ".lst", budget)
                for ligne in (brut or b"").decode("utf-8", "replace").splitlines():
                    n = domaines.valider(ligne)
                    if n:
                        noms.append(n)
        finally:
            os.close(fd_cat)
    finally:
        os.close(fd_listes)
    return dedoublonner(noms)
