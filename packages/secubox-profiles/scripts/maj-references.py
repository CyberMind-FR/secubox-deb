#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: profiles — met à jour les profils de référence NON MODIFIÉS de /etc/secubox/profiles (#3218).

Le postinst ne semait les profils qu'à la première installation : une mise à jour du paquet ne changeait jamais
/etc/secubox/profiles/minimal.toml, et `secubox-profilectl apply --profile minimal` appliquait l'ANCIEN profil. Règle :
une copie identique, octet pour octet, à une version déjà LIVRÉE de ce profil (empreintes-livrees.txt, tirées de
l'historique git) n'a pas été modifiée par l'opérateur : on la remplace. Une copie modifiée (à la main, ou réécrite par
le panneau) est gardée ; la nouvelle référence est posée à côté en <nom>.toml.dpkg-dist.

POURQUOI PAR DESCRIPTEUR (relecture de #3248). Ce programme tourne en ROOT (postinst, donc chaque nuit par majauto),
alors que /etc/secubox et /etc/secubox/profiles appartiennent au compte partagé `secubox`. La première version (bash)
créait un temporaire DANS la cible puis le copiait, chmod et chown par chemin : un lien substitué entre deux commandes
élevait secubox en root. Un dossier `profiles` remplacé par un lien la faisait écrire dans un dossier root, et une FIFO
posée à la place d'un profil bloquait dpkg sans fin. Ici :
  * la cible est ouverte composant par composant sans suivre de lien (O_NOFOLLOW) : un lien de dossier est refusé ;
  * chaque fichier est CRÉÉ dans un dossier temporaire root seul (0700) sous PREPA (/etc, même système de fichiers),
    puis RENOMMÉ dans la cible par descripteur (renameat) : rien n'est jamais écrit au travers d'un nom de la cible ;
  * une copie locale n'est lue que si c'est un fichier ordinaire (fstat sur le descripteur ouvert sans suivre de lien
    et sans bloquer), et au plus TAILLE_MAX octets ; un lien, une FIFO, un dossier sont laissés et signalés.

Usage : maj-references.py [SOURCE] [CIBLE] [EMPREINTES]   (env. PREPA=/etc, PROPRIO=utilisateur:groupe en postinst)
Lancé par le postinst en `python3 -I` (aucun module pris dans le dossier courant)."""
from __future__ import annotations

import errno
import grp
import hashlib
import os
import pwd
import stat
import sys
import tempfile
from pathlib import Path

TAILLE_MAX = 1 << 20          # un profil fait quelques Ko ; au-delà, la copie est tenue pour modifiée
PREFIXE_PREPA = ".secubox-profiles."


def dire(message: str) -> None:
    print(f"secubox-profiles : {message}", file=sys.stderr)


def ouvrir_dossier(chemin: Path) -> int:
    """Descripteur du dossier `chemin`, ouvert depuis / composant par composant SANS suivre aucun lien."""
    chemin = Path(os.path.abspath(chemin))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in chemin.parts[1:]:
            suivant = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = suivant
    except OSError:
        os.close(fd)
        raise
    return fd


def lire_local(nom: str, dossier_fd: int) -> tuple[str, bytes | None]:
    """(« absent » | « ordinaire » | « lien » | « autre », contenu borné ou None). Ne suit pas de lien, ne bloque pas."""
    try:
        fd = os.open(nom, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dossier_fd)
    except FileNotFoundError:
        return "absent", None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return "lien", None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "autre", None
        if st.st_size > TAILLE_MAX:
            return "ordinaire", b""                      # trop gros pour une référence : jamais reconnu comme livré
        morceaux, total = [], 0
        while total <= TAILLE_MAX:
            bloc = os.read(fd, 65536)
            if not bloc:
                break
            morceaux.append(bloc)
            total += len(bloc)
        return "ordinaire", b"".join(morceaux)[:TAILLE_MAX + 1]
    finally:
        os.close(fd)


def proprietaire(proprio: str | None) -> tuple[int, int] | None:
    if not proprio:
        return None
    utilisateur, _, groupe = proprio.partition(":")
    return pwd.getpwnam(utilisateur).pw_uid, grp.getgrnam(groupe or utilisateur).gr_gid


def poser(contenu: bytes, nom_final: str, prepa_fd: int, cible_fd: int, ids: tuple[int, int] | None) -> None:
    """Crée le fichier dans le dossier root seul, puis le renomme dans la cible (remplace un lien, ne le suit jamais)."""
    tmp = f"{nom_final}.prepa"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=prepa_fd)
    try:
        os.write(fd, contenu)
        os.fchmod(fd, 0o644)
        if ids is not None:
            os.fchown(fd, *ids)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.rename(tmp, nom_final, src_dir_fd=prepa_fd, dst_dir_fd=cible_fd)
    except OSError:
        os.unlink(tmp, dir_fd=prepa_fd)
        raise


def maj(source: Path, cible: Path, empreintes: Path, *, prepa: Path = Path("/etc"), proprio: str | None = None) -> int:
    source, cible, empreintes = Path(source), Path(cible), Path(empreintes)
    try:
        cible_fd = ouvrir_dossier(cible)
    except FileNotFoundError:
        dire(f"{cible} absent, rien à mettre à jour")
        return 0
    except OSError as exc:
        dire(f"{cible} refusé (lien ou dossier invalide dans le chemin : {exc.strerror}) ; profils non mis à jour")
        return 1
    try:
        livrees = set(empreintes.read_text(encoding="utf-8").splitlines()) if empreintes.is_file() else set()
        ids = proprietaire(proprio)
        prepa_dossier = tempfile.mkdtemp(prefix=PREFIXE_PREPA, dir=prepa)            # 0700, propriétaire : nous (root)
        prepa_fd = ouvrir_dossier(Path(prepa_dossier))
        try:
            if os.fstat(prepa_fd).st_dev != os.fstat(cible_fd).st_dev:
                dire(f"{prepa} et {cible} ne sont pas sur le même système de fichiers ; profils non mis à jour")
                return 1
            for ref in sorted(source.glob("*.toml")):
                if ref.is_symlink() or not ref.is_file():
                    continue
                _un_profil(ref, livrees, prepa_fd, cible_fd, ids)
        finally:
            for reste in os.listdir(prepa_fd):
                os.unlink(reste, dir_fd=prepa_fd)
            os.close(prepa_fd)
            os.rmdir(prepa_dossier)
    finally:
        os.close(cible_fd)
    return 0


def _un_profil(ref: Path, livrees: set[str], prepa_fd: int, cible_fd: int, ids) -> None:
    nom, neuf = ref.name, ref.read_bytes()
    etat, local = lire_local(nom, cible_fd)
    try:
        if etat == "lien":
            dire(f"{nom} est un lien, non touché")
        elif etat == "autre":
            dire(f"{nom} n'est pas un fichier ordinaire, non touché")
        elif etat == "absent":
            poser(neuf, nom, prepa_fd, cible_fd, ids)
            dire(f"profil {nom} installé")
        elif local == neuf:
            return
        elif f"{hashlib.sha256(local).hexdigest()}  {nom}" in livrees:
            poser(neuf, nom, prepa_fd, cible_fd, ids)
            try:
                os.unlink(f"{nom}.dpkg-dist", dir_fd=cible_fd)
            except FileNotFoundError:
                pass
            dire(f"profil {nom} mis à jour (copie non modifiée d'une version livrée)")
        else:
            poser(neuf, f"{nom}.dpkg-dist", prepa_fd, cible_fd, ids)
            dire(f"{nom} modifié localement, gardé ; nouvelle référence : {nom}.dpkg-dist")
    except OSError as exc:
        dire(f"écriture de {nom} impossible : {exc.strerror}")


def main(argv: list[str]) -> int:
    source = Path(argv[1]) if len(argv) > 1 else Path("/usr/share/secubox/profiles")
    cible = Path(argv[2]) if len(argv) > 2 else Path("/etc/secubox/profiles")
    empreintes = Path(argv[3]) if len(argv) > 3 else source / "empreintes-livrees.txt"
    return maj(source, cible, empreintes, prepa=Path(os.environ.get("PREPA", "/etc")),
               proprio=os.environ.get("PROPRIO") or None)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
