# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Remet des LIENS dans sites-enabled (#2253).

`sed -i` (secubox-vhost-logs) et `os.replace` (nginx-sync) sur un lien le remplacent par un fichier ordinaire : sites-enabled se couvre de COPIES, et
sites-available (que les paquets possèdent) diverge en silence de ce que nginx charge. Sur gk2, 19 copies ; PhotoPrism avait le bon ordre d'includes dans
sites-available et le mauvais dans la copie — la réparation de l'un ne changeait rien à l'autre.

Ce que nginx charge est la RÉFÉRENCE : la copie est ADOPTÉE dans sites-available (jamais l'inverse, qui changerait le comportement). Trois cas :
  lier      la copie est identique à sites-available : on remplace par un lien ;
  adopter   la copie diffère : l'ancienne version de sites-available est sauvegardée, la copie la remplace, puis lien ;
  deplacer  aucune version dans sites-available : la copie y est déplacée, puis lien ;
  refuser   la « version » de sites-available est elle-même un lien (on n'écrit jamais à travers un lien) : rien n'est touché.
Les sauvegardes vont HORS de sites-enabled (nginx inclut tout ce répertoire). `nginx -t` valide ; en cas d'échec, tout est rendu tel qu'avant.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Callable, List

IGNORES = (".bak", ".dpkg", ".pre-", "~", ".avant-", ".orig", ".tmp")


def _ignore(nom: str) -> bool:
    return any(x in nom for x in IGNORES)


def plan(enabled: Path, available: Path) -> List[dict]:
    out: List[dict] = []
    for p in sorted(Path(enabled).iterdir()):
        if p.is_symlink() or not p.is_file() or _ignore(p.name):
            continue
        cible = Path(available) / p.name
        if cible.is_symlink():
            out.append({"nom": p.name, "action": "refuser"})
        elif not cible.exists():
            out.append({"nom": p.name, "action": "deplacer"})
        elif cible.read_bytes() == p.read_bytes():
            out.append({"nom": p.name, "action": "lier"})
        else:
            out.append({"nom": p.name, "action": "adopter"})
    return out


def _ecrire_atomique(chemin: Path, contenu: bytes, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=f".{chemin.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(contenu)
        os.chmod(tmp, mode)
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _lier(enabled: Path, nom: str) -> None:
    tmp = enabled / f".{nom}.lien.tmp"
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    os.symlink(f"../sites-available/{nom}", tmp)
    os.replace(tmp, enabled / nom)


def apply(actions: List[dict], enabled: Path, available: Path, sauvegardes: Path, run: Callable[[list], tuple]) -> dict:
    enabled, available, sauvegardes = Path(enabled), Path(available), Path(sauvegardes)
    rep = {"relies": [], "refuses": [a["nom"] for a in actions if a["action"] == "refuser"], "recharge": False, "retour_arriere": False}
    faits = [a for a in actions if a["action"] != "refuser"]
    if not faits:
        return rep
    passe = sauvegardes / f"relink-{time.strftime('%Y%m%d%H%M%S')}-{os.getpid()}"
    (passe / "enabled").mkdir(parents=True)
    (passe / "available").mkdir()
    existait = {}
    for a in faits:
        nom = a["nom"]
        shutil.copy2(enabled / nom, passe / "enabled" / nom)
        existait[nom] = (available / nom).exists()
        if existait[nom]:
            shutil.copy2(available / nom, passe / "available" / nom)
    for a in faits:
        nom = a["nom"]
        src = (passe / "enabled" / nom)
        if a["action"] in ("adopter", "deplacer"):
            _ecrire_atomique(available / nom, src.read_bytes(), 0o644)
        _lier(enabled, nom)
        rep["relies"].append(nom)
    rc, _ = run(["nginx", "-t"])
    if rc != 0:
        for a in faits:                               # tout est rendu comme avant : copies d'abord, puis sites-available
            nom = a["nom"]
            if (enabled / nom).is_symlink():
                (enabled / nom).unlink()
            shutil.copy2(passe / "enabled" / nom, enabled / nom)
            if existait[nom]:
                shutil.copy2(passe / "available" / nom, available / nom)
            elif (available / nom).exists():
                (available / nom).unlink()
        rep["relies"], rep["retour_arriere"] = [], True
        return rep
    run(["systemctl", "reload", "nginx"])
    rep["recharge"] = True
    return rep
