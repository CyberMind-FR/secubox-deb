# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Fichiers du mode routeur (#3189) : lecture sans lien, écriture atomique, sauvegardes 4R. Aucune commande externe."""
from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

GARDER = 4
_NOM = re.compile(r"(\d{8}T\d{6}Z)(?:-(\d+))?")


class LienSymbolique(OSError):
    """Un chemin géré est un lien symbolique : ni suivi, ni remplacé."""


def creer_dossiers(dossier: Path, mode: int) -> None:
    manquants = []
    d = dossier
    while not os.path.lexists(d):
        manquants.append(d)
        d = d.parent
    for d in reversed(manquants):
        with contextlib.suppress(FileExistsError):
            os.mkdir(d, mode)
        os.chmod(d, mode)  # l'umask de sudo (0027) ne doit pas resserrer un dossier lu par les démons


def lire(chemin: Path) -> bytes | None:
    """Contenu d'un fichier, None s'il est absent ; un lien symbolique n'est jamais suivi."""
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise LienSymbolique(errno.ELOOP, "lien symbolique refusé", str(chemin)) from exc
        raise
    with os.fdopen(fd, "rb") as f:
        return f.read()


def _fsync_dossier(dossier: Path) -> None:
    fd = os.open(dossier, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ecrire(chemin: Path, contenu: bytes | str, mode: int) -> None:
    """Temporaire dans le même dossier, fsync, os.replace : jamais de fichier à moitié écrit."""
    if isinstance(contenu, str):
        contenu = contenu.encode("utf-8")
    if chemin.is_symlink():
        raise LienSymbolique(errno.ELOOP, "lien symbolique refusé", str(chemin))
    creer_dossiers(chemin.parent, 0o755)
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=f".{chemin.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(contenu)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    _fsync_dossier(chemin.parent)


def _cle(nom: str) -> tuple[str, int]:
    m = _NOM.fullmatch(nom)
    if m is None:
        return (nom, 0)
    return (m.group(1), int(m.group(2) or 1))


def sauvegardes(base: Path) -> list[str]:
    """Noms des sauvegardes complètes, de la plus ancienne à la plus récente."""
    if not base.is_dir():
        return []
    noms = [d.name for d in base.iterdir() if _NOM.fullmatch(d.name) and d.is_dir() and not d.is_symlink()]
    return sorted(noms, key=_cle)


def sauvegarder(base: Path, horodatage: str, geres: dict[str, Path], proteger: str | None = None) -> str:
    """Copie des chemins gérés présents + absents.json, posée d'un bloc (renommage) ; garde les 4 plus récentes,
    plus `proteger` (celle de la dernière application réussie). `geres` : chemin de référence → chemin réel."""
    creer_dossiers(base, 0o750)
    for reste in base.glob(".en-cours-*"):                       # sauvegarde interrompue : jamais complète
        shutil.rmtree(reste)
    nom, n = horodatage, 1
    while os.path.lexists(base / nom):
        n += 1
        nom = f"{horodatage}-{n}"
    tmp = Path(tempfile.mkdtemp(dir=base, prefix=".en-cours-"))
    try:
        absents = []
        for reference, reel in geres.items():
            contenu = lire(reel)
            if contenu is None:
                absents.append(reference)
            else:
                ecrire(tmp / reference.lstrip("/"), contenu, 0o640)
        ecrire(tmp / "absents.json", json.dumps(absents, ensure_ascii=False, indent=1) + "\n", 0o640)
        os.chmod(tmp, 0o750)
        os.rename(tmp, base / nom)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    for ancien in sauvegardes(base)[:-GARDER]:
        if ancien != proteger:
            shutil.rmtree(base / ancien)
    return nom


def restaurer(dossier: Path, geres: dict[str, Path], modes: dict[str, int]) -> tuple[list[str], list[str]]:
    """Réécrit chaque fichier sauvegardé, supprime ceux qui étaient absents ; continue après une erreur.
    Renvoie (chemins absents de la sauvegarde, erreurs)."""
    brut = lire(dossier / "absents.json")
    try:
        absents = json.loads((brut or b"").decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise OSError(f"{dossier.name}/absents.json illisible") from exc
    if not isinstance(absents, list):
        raise OSError(f"{dossier.name}/absents.json n'est pas une liste")
    erreurs: list[str] = []
    for reference, reel in geres.items():                        # seuls les chemins gérés : rien d'autre n'est touché
        try:
            if reference in absents:
                reel.unlink(missing_ok=True)
                continue
            contenu = lire(dossier / reference.lstrip("/"))
            if contenu is None:
                erreurs.append(f"{reference} : absent de la sauvegarde {dossier.name}")
                continue
            ecrire(reel, contenu, modes.get(reference, 0o644))
        except OSError as exc:
            erreurs.append(f"{reference} : {exc}")
    return absents, erreurs
