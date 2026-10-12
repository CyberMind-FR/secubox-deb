# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Ce que le dépôt PUBLIE réellement (#2493), lu dans l'arborescence que nginx sert (`dists/` et `pool/`), en lecture seule.

`repoctl` interroge le socle reprepro de `REPO_BASE`, qui peut n'être PAS celui du dépôt publié (sur gk2 : un autre dossier) : la page annonçait « 0 paquet » et « trixie : 0 »
pour un dépôt qui en publie des centaines. Les fichiers Release et Packages sont publics (le dépôt est servi tel quel) : on lit l'entête Release et les noms de paquets,
jamais la base ni les clés. Source absente ou illisible : null, jamais un zéro inventé."""
from __future__ import annotations

import os
import re
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Optional

_MAX_PACKAGES = 30 * 1024 * 1024
_CHAMPS = ("Origin", "Label", "Suite", "Codename", "Date", "Architectures", "Components", "Version", "Description")
MAX_FICHIERS = 200_000
BUDGET_S = 3.0


def _release(chemin: Path) -> Optional[dict]:
    try:
        entete = {}
        with open(chemin, encoding="utf-8", errors="replace") as f:
            for ligne in f:
                if ligne.startswith((" ", "\t")):
                    break                                   # fin de l'entête : les sommes de contrôle suivent
                k, _, v = ligne.partition(":")
                if k in _CHAMPS:
                    entete[k] = v.strip()
        return entete or None
    except OSError:
        return None


def _noms(chemin: Path) -> Optional[set]:
    """Noms de paquets d'un fichier Packages, ou None s'il est absent, illisible ou trop gros."""
    try:
        if chemin.stat().st_size > _MAX_PACKAGES:
            return None
        noms = set()
        with open(chemin, "rb") as f:
            for ligne in f:
                if ligne.startswith(b"Package: "):
                    noms.add(ligne[9:].strip().decode("utf-8", "replace"))
        return noms
    except OSError:
        return None


def _pool(dossier: Path, max_fichiers: int, budget_s: float) -> Optional[dict]:
    if not dossier.is_dir():
        return None
    debut = time.monotonic()
    octets = n = 0
    recent: Optional[float] = None
    partiel = False
    pile = [str(dossier)]
    while pile and not partiel:
        d = pile.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            pile.append(e.path)
                        elif e.name.endswith(".deb") and e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            octets += st.st_size
                            n += 1
                            recent = st.st_mtime if recent is None or st.st_mtime > recent else recent
                    except OSError:
                        continue
                    if n >= max_fichiers or time.monotonic() - debut > budget_s:
                        partiel = True
                        break
        except OSError:
            partiel = True
    return {"octets": octets, "paquets_deb": n, "recent": recent, "partiel": partiel}


def lire(racine: Path, max_fichiers: int = MAX_FICHIERS, budget_s: float = BUDGET_S) -> dict:
    racine = Path(racine)
    dists = racine / "dists"
    try:
        noms = sorted(p.name for p in dists.iterdir() if p.is_dir())
    except OSError:
        return {"disponible": False, "racine": str(racine), "suites": [], "pool": None, "paquets_uniques": None, "derniere_publication": None}
    suites, tous = [], set()
    visible = False
    for nom in noms:
        rel = _release(dists / nom / "Release")
        if rel is None:
            continue                                        # dossier sans Release (copie, sauvegarde) : pas une suite publiée
        archs = [a for a in rel.get("Architectures", "").split() if re.fullmatch(r"[a-z0-9-]+", a) and a != "source"]
        comps = [c for c in rel.get("Components", "").split() if re.fullmatch(r"[A-Za-z0-9/_-]+", c)]
        par_arch, uniques = {}, set()
        for a in archs:
            tot, vu = 0, False
            for c in comps:
                ns = _noms(dists / nom / c / f"binary-{a}" / "Packages")
                if ns is not None:
                    tot += len(ns); vu = True; uniques |= ns
            par_arch[a] = tot if vu else None
        lisibles = [n for n in par_arch.values() if n is not None]
        visible = visible or bool(lisibles)
        tous |= {(nom, n) for n in uniques}
        suites.append({"nom": nom, "codename": rel.get("Codename"), "version": rel.get("Version"), "date": rel.get("Date"), "label": rel.get("Label"),
                       "architectures": archs, "composants": comps, "paquets": par_arch, "uniques": len(uniques) if lisibles else None})
    dates = []
    for s_ in suites:
        try:
            dates.append((parsedate_to_datetime(s_["date"]), s_["date"]))     # en DATE : « Mon, 24 Aug » est alphabétiquement après « Mon, 12 Oct »
        except (TypeError, ValueError):
            continue
    derniere = max(dates)[1] if dates else None
    return {"disponible": True, "racine": str(racine), "suites": suites, "pool": _pool(racine / "pool", max_fichiers, budget_s),
            "paquets_uniques": len({n for _, n in tous}) if visible else None, "derniere_publication": derniere}
