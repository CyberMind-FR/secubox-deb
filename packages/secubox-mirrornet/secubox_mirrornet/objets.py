# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dépôt des objets des jeux de données (#3653) : fichiers OPAQUES nommés par leur empreinte BLAKE2b-256, jamais
extraits par MirrorNet (le module consommateur extrait sous son compte, `docs/mirrornet/architecture.md` décision 1).

Écriture en flux dans un temporaire du même dossier (O_EXCL, 0640), empreinte calculée au passage, taille plafonnée,
renommage atomique seulement si l'empreinte attendue (quand il y en a une) correspond. Garde d'espace : jamais sous
`reserve` Mio libres après écriture.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Tuple

from . import config

EMPREINTE = re.compile(r"^b2:[0-9a-f]{64}$")
log = logging.getLogger("secubox-mirrornet")


class RefusObjet(Exception):
    """Objet refusé (taille, espace, empreinte) : rien n'est gardé."""


def dossier() -> Path:
    d = config.OBJETS
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def chemin(empreinte: str) -> Path:
    if not EMPREINTE.match(empreinte or ""):
        raise RefusObjet("empreinte invalide")
    return dossier() / empreinte[3:]


def present(empreinte: str) -> bool:
    try:
        return chemin(empreinte).is_file()
    except RefusObjet:
        return False


def verifier_espace(taille: int, reserve_mo: int) -> None:
    libre = shutil.disk_usage(dossier()).free
    if libre - taille < reserve_mo * 1024 * 1024:
        raise RefusObjet(f"espace insuffisant ({libre // (1024 * 1024)} Mio libres, réserve {reserve_mo} Mio)")


class Ecrivain:
    """Écriture incrémentale d'un objet (dépôt par l'API, réception d'un pair) : rien n'est tenu en mémoire au-delà d'un
    morceau. `terminer` vérifie et renomme ; toute erreur ou `abandonner` efface le temporaire."""

    def __init__(self, taille_max: int):
        self.taille_max, self.taille = taille_max, 0
        self.h = hashlib.blake2b(digest_size=32)
        self.tmp = dossier() / f".recu.{os.getpid()}.{os.urandom(6).hex()}"
        self.f = os.fdopen(os.open(self.tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640), "wb")

    def ajouter(self, m: bytes) -> None:
        self.taille += len(m)
        if self.taille > self.taille_max:
            self.abandonner()
            raise RefusObjet(f"objet trop volumineux (plafond {self.taille_max} octets)")
        self.h.update(m)
        self.f.write(m)

    def terminer(self, attendue: Optional[str] = None, taille_attendue: Optional[int] = None) -> Tuple[str, int]:
        try:
            self.f.flush()
            os.fsync(self.f.fileno())
            self.f.close()
            empreinte = "b2:" + self.h.hexdigest()
            if attendue is not None and empreinte != attendue:
                raise RefusObjet("empreinte différente de celle annoncée")
            if taille_attendue is not None and self.taille != taille_attendue:
                raise RefusObjet("taille différente de celle annoncée")
            os.replace(self.tmp, dossier() / empreinte[3:])
            return empreinte, self.taille
        except BaseException:
            self.abandonner()
            raise

    def abandonner(self) -> None:
        try:
            self.f.close()
        except OSError:
            pass
        try:
            os.unlink(self.tmp)
        except OSError:
            pass


def ecrire(morceaux: Iterable[bytes], taille_max: int, attendue: Optional[str] = None,
           taille_attendue: Optional[int] = None) -> Tuple[str, int]:
    """Écrit un flux ; rend (empreinte, taille). Dépassement, empreinte ou taille différentes : RefusObjet, rien gardé."""
    e = Ecrivain(taille_max)
    try:
        for m in morceaux:
            e.ajouter(m)
    except BaseException:
        e.abandonner()
        raise
    return e.terminer(attendue, taille_attendue)


def noter(cx: sqlite3.Connection, empreinte: str, taille: int, source: str) -> None:
    cx.execute("INSERT INTO objet(empreinte, taille, source, stocke_le) VALUES (?,?,?,?) ON CONFLICT(empreinte) DO NOTHING",
               (empreinte, taille, source, datetime.now(timezone.utc).isoformat()))


def supprimer(cx: sqlite3.Connection, empreinte: str) -> bool:
    """Efface l'objet et sa ligne ; un échec (autre que « déjà absent ») est journalisé et la ligne GARDÉE, pour un
    nouvel essai à la passe suivante. Rend True quand l'objet n'est plus sur disque."""
    try:
        chemin(empreinte).unlink()
    except FileNotFoundError:
        pass
    except (OSError, RefusObjet) as e:
        log.warning("mirrornet : objet %s non effacé : %s", empreinte[:19], e)
        return False
    cx.execute("DELETE FROM objet WHERE empreinte = ?", (empreinte,))
    return True


def nettoyer_temporaires() -> None:
    """Restes d'un transfert interrompu (arrêt du service) : supprimés au démarrage."""
    for p in dossier().glob(".recu.*"):
        try:
            p.unlink()
        except OSError as e:
            log.warning("mirrornet : temporaire %s non effacé : %s", p.name, e)
