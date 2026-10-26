# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Fichiers du mode routeur (#3189) : lecture sans lien, écriture atomique, sauvegardes 4R. Aucune commande externe.

Un paramètre `racine` active le contrôle strict (`verifier_sur`) : chaque composant du chemin sous la racine appartient à
l'utilisateur courant, n'est inscriptible ni par le groupe ni par les autres, et n'est pas un lien — sinon un autre compte
(secubox possède /var/lib/secubox et /etc/secubox) pourrait substituer un dossier entier par le sien."""
from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path

GARDER = 4
_NOM = re.compile(r"\d{8}T\d{6}Z(?:-\d+)?")


class LienSymbolique(OSError):
    """Un chemin géré est un lien symbolique : ni suivi, ni remplacé."""


class CheminNonSur(OSError):
    """Un composant du chemin pourrait être substitué par un autre compte."""


def verifier_sur(racine: Path, chemin: Path) -> None:
    courant = racine
    for partie in chemin.relative_to(racine).parts:
        courant = courant / partie
        try:
            st = os.lstat(courant)
        except FileNotFoundError:
            return                                          # la suite n'existe pas : nous la créerons
        if stat.S_ISLNK(st.st_mode):
            raise CheminNonSur(f"{courant} est un lien symbolique")
        if st.st_uid != os.geteuid():
            raise CheminNonSur(f"{courant} appartient à l'uid {st.st_uid}, pas à l'uid {os.geteuid()} du contrôleur")
        if st.st_mode & 0o022:
            raise CheminNonSur(f"{courant} est inscriptible par le groupe ou les autres ({stat.filemode(st.st_mode)})")


def creer_dossiers(dossier: Path, mode: int, racine: Path | None = None) -> None:
    if racine is not None:
        verifier_sur(racine, dossier)                       # un dossier déjà là doit être sûr, pas seulement accepté
    manquants = []
    d = dossier
    while not os.path.lexists(d):
        manquants.append(d)
        d = d.parent
    for d in reversed(manquants):
        with contextlib.suppress(FileExistsError):
            os.mkdir(d, mode)
        os.chmod(d, mode)  # l'umask de sudo (0027) ne doit pas resserrer un dossier lu par les démons


def lire(chemin: Path, racine: Path | None = None) -> bytes | None:
    """Contenu d'un fichier, None s'il est absent ; un lien symbolique n'est jamais suivi."""
    if racine is not None:
        verifier_sur(racine, chemin)
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


def ecrire(chemin: Path, contenu: bytes | str, mode: int, racine: Path | None = None) -> None:
    """Temporaire dans le même dossier, fsync, os.replace : jamais de fichier à moitié écrit.
    Avec `racine` : contrôle strict et dossiers manquants créés en 0700."""
    if isinstance(contenu, str):
        contenu = contenu.encode("utf-8")
    if racine is not None:
        verifier_sur(racine, chemin)
    if chemin.is_symlink():
        raise LienSymbolique(errno.ELOOP, "lien symbolique refusé", str(chemin))
    creer_dossiers(chemin.parent, 0o755 if racine is None else 0o700, racine)
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


def _sequence(dossier: Path, racine: Path) -> int:
    try:
        return int((lire(dossier / "sequence", racine) or b"").decode("ascii").strip())
    except (ValueError, UnicodeDecodeError):
        return 0                                            # séquence illisible : tenue pour la plus ancienne


def sauvegardes(base: Path, racine: Path) -> list[str]:
    """Noms des sauvegardes complètes, de la plus ancienne à la plus récente — par séquence, jamais par l'horloge
    (une horloge remise en arrière ferait passer la sauvegarde neuve pour la plus vieille)."""
    verifier_sur(racine, base)
    if not base.is_dir():
        return []
    noms = [d.name for d in base.iterdir() if _NOM.fullmatch(d.name) and d.is_dir() and not d.is_symlink()]
    return sorted(noms, key=lambda n: (_sequence(base / n, racine), n))


def sauvegarder(base: Path, horodatage: str, geres: dict[str, Path], racine: Path, stricts: frozenset[str],
                proteger: str | None = None) -> str:
    """Copie des chemins gérés présents + absents.json + sequence, posée d'un bloc (renommage) ; garde les 4 plus
    récentes, plus la neuve et `proteger` (celle de la dernière application réussie). `geres` : référence → chemin réel ;
    les références de `stricts` sont lues sous contrôle strict."""
    creer_dossiers(base, 0o700, racine)
    for reste in base.glob(".en-cours-*"):                  # sauvegarde interrompue : jamais complète
        shutil.rmtree(reste)
    sequence = max((_sequence(base / n, racine) for n in sauvegardes(base, racine)), default=0) + 1
    nom, n = horodatage, 1
    while os.path.lexists(base / nom):
        n += 1
        nom = f"{horodatage}-{n}"
    tmp = Path(tempfile.mkdtemp(dir=base, prefix=".en-cours-"))
    try:
        absents = []
        for reference, reel in geres.items():
            contenu = lire(reel, racine if reference in stricts else None)
            if contenu is None:
                absents.append(reference)
            else:
                ecrire(tmp / reference.lstrip("/"), contenu, 0o640, racine)
        ecrire(tmp / "absents.json", json.dumps(absents, ensure_ascii=False, indent=1) + "\n", 0o640, racine)
        ecrire(tmp / "sequence", f"{sequence}\n", 0o640, racine)
        os.rename(tmp, base / nom)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    for ancien in sauvegardes(base, racine)[:-GARDER]:
        if ancien not in (nom, proteger):
            shutil.rmtree(base / ancien)
    return nom


def restaurer(dossier: Path, geres: dict[str, Path], modes: dict[str, int], racine: Path,
              stricts: frozenset[str], neutres: dict[str, str] | None = None) -> tuple[list[str], list[str]]:
    """Réécrit chaque fichier sauvegardé, supprime ceux qui étaient absents ; continue après une erreur.
    Une référence de `neutres` n'est jamais supprimée (un autre paquet l'inclut nommément) : absente de la sauvegarde,
    elle reçoit son contenu neutre si son dossier existe, et rien sinon. Renvoie (chemins absents, erreurs)."""
    neutres = neutres or {}
    brut = lire(dossier / "absents.json", racine)
    try:
        absents = json.loads((brut or b"").decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise OSError(f"{dossier.name}/absents.json illisible") from exc
    if not isinstance(absents, list):
        raise OSError(f"{dossier.name}/absents.json n'est pas une liste")
    erreurs: list[str] = []
    for reference, reel in geres.items():                   # seuls les chemins gérés : rien d'autre n'est touché
        strict = racine if reference in stricts else None
        try:
            if reference in absents and reference in neutres:
                if reel.parent.is_dir():
                    ecrire(reel, neutres[reference], modes.get(reference, 0o644), strict)
                continue
            if reference in absents:
                if strict is not None:
                    verifier_sur(racine, reel)
                reel.unlink(missing_ok=True)
                continue
            contenu = lire(dossier / reference.lstrip("/"), racine)
            if contenu is None:
                erreurs.append(f"{reference} : absent de la sauvegarde {dossier.name}")
                continue
            ecrire(reel, contenu, modes.get(reference, 0o644), strict)
        except OSError as exc:
            erreurs.append(f"{reference} : {exc}")
    return absents, erreurs
