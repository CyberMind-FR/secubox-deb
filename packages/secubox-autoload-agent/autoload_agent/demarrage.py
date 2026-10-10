# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Démarrage automatique Auto-Load (#2280) : le jeton, posé par l'atelier sur la partition de démarrage, est installé là où le moteur le lit (/etc/secubox/secrets,
0600, root) puis EFFACÉ de /boot — une partition FAT lisible de tous ne garde pas un secret. Le jeton est à usage unique et lié à la clé WireGuard de la box
à la réclamation : même lu avant l'effacement, il ne sert qu'une fois."""
from __future__ import annotations

import os
import re
from pathlib import Path

SOURCE = Path("/boot/secubox/autoload/jeton")
DESTINATION = Path("/etc/secubox/secrets/autoload-jeton")
_JETON = re.compile(r"^gk2_[0-9a-f]{32}\n?$")


def _effacer(source: Path) -> None:
    """Écrase puis supprime (au mieux : sur FAT ou flash, l'écrasement n'est pas garanti ; c'est l'usage unique du jeton qui protège)."""
    try:
        taille = source.stat().st_size
        with open(source, "r+b") as f:
            f.write(b"\0" * taille)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        source.unlink()
    except OSError:
        pass


def installer_jeton(source: Path = SOURCE, destination: Path = DESTINATION) -> str:
    """Rend : `absent` (rien à faire), `installe`, `deja_present` (reprise : le jeton d'un enrôlement en cours n'est pas remplacé), `refuse` (mal formé ou lien symbolique)."""
    if not os.path.lexists(source):
        return "absent"
    if source.is_symlink() or not source.is_file():
        return "refuse"                                           # jamais suivi, jamais effacé : ce n'est pas notre fichier
    try:
        texte = source.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        return "refuse"
    if not _JETON.match(texte):
        return "refuse"                                           # laissé en place pour que l'atelier le voie ; aucune valeur n'est journalisée
    if destination.exists():
        _effacer(source)
        return "deja_present"
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(texte.strip() + "\n")
    os.chmod(destination, 0o600)
    _effacer(source)
    return "installe"
