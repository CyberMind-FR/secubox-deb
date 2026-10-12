# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dépôt APT hébergé par la box (#2471), en lecture seule : suites, architectures, composants, nombre de paquets et taille du pool.

C'est le vrai « miroir » de la box : l'ancien module Mirror gérait des miroirs distants que rien ne synchronisait. Les fichiers Release et Packages sont publics (le dépôt
est servi tel quel) : seuls l'entête Release et le NOMBRE de paquets sont lus, jamais les clés du dépôt ni sa base. Source absente ou illisible : `null`."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from . import caches

RACINE = Path("/data/apt")
_MAX_PACKAGES = 30 * 1024 * 1024
_CHAMPS = ("Origin", "Label", "Suite", "Codename", "Date", "Architectures", "Components", "Version")


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


def _paquets(chemin: Path) -> Optional[int]:
    try:
        if chemin.stat().st_size > _MAX_PACKAGES:
            return None
        n = 0
        with open(chemin, "rb") as f:
            for ligne in f:
                if ligne.startswith(b"Package: "):
                    n += 1
        return n
    except OSError:
        return None


def lire(racine: Path = RACINE, **k) -> dict:
    dists = racine / "dists"
    try:
        noms = sorted(p.name for p in dists.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return {"disponible": False, "racine": str(racine), "suites": [], "pool": None, "paquets_total": None}
    suites = []
    for nom in noms:
        rel = _release(dists / nom / "Release")
        if rel is None:
            continue                                        # dossier sans Release (copie, sauvegarde) : pas une suite publiée
        archs = [a for a in rel.get("Architectures", "").split() if re.fullmatch(r"[a-z0-9-]+", a)]
        comps = [c for c in rel.get("Components", "").split() if re.fullmatch(r"[A-Za-z0-9/_-]+", c)]
        par_arch = {}
        for a in archs:
            tot, vu = 0, False
            for c in comps:
                n = _paquets(dists / nom / c / f"binary-{a}" / "Packages")
                if n is not None:
                    tot += n; vu = True
            par_arch[a] = tot if vu else None
        suites.append({"nom": nom, "codename": rel.get("Codename"), "date": rel.get("Date"), "version": rel.get("Version"), "label": rel.get("Label"),
                       "architectures": archs, "composants": comps, "paquets": par_arch})
    pool = caches.mesurer(racine / "pool", **k) if (racine / "pool").is_dir() else None
    total = None
    comptes = [n for s in suites for n in s["paquets"].values() if n is not None]
    if comptes:
        total = sum(comptes)
    return {"disponible": True, "racine": str(racine), "suites": suites, "pool": pool, "paquets_total": total}
