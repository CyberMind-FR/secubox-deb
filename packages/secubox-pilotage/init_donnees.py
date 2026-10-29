# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Prépare le dossier de données du module (#3126) : `init_donnees.py PARENT NOM UTILISATEUR [MODE]`, lancé en root par le postinst
(`python3 -I`). Remplace `install -d` et `chown` par chemin, qui suivent les liens : /var/lib/secubox appartient au compte partagé
secubox, qui pourrait y planter un lien entre deux commandes. Ici tout passe par descripteur : parent ouvert O_NOFOLLOW|O_DIRECTORY, enfant
créé (mkdirat) ou ouvert O_NOFOLLOW|O_DIRECTORY relatif au parent, puis fchown/fchmod sur le descripteur. Un lien à la place du dossier est
remplacé par un vrai dossier (le lien seul est délié, jamais sa cible) ; un fichier ordinaire est refusé. systemd-tmpfiles n'est pas utilisé :
il refuse ces chemins (« unsafe path transition »).
"""
import errno
import os
import pwd
import stat
import sys

DRAPEAUX = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def preparer(parent: str, nom: str, utilisateur: str, mode: int = 0o750) -> None:
    if "/" in nom or nom in ("", ".", ".."):
        raise ValueError(f"nom de dossier invalide : {nom!r}")
    compte = pwd.getpwnam(utilisateur)
    fd_parent = os.open(parent, DRAPEAUX)
    try:
        try:
            etat = os.stat(nom, dir_fd=fd_parent, follow_symlinks=False)
        except FileNotFoundError:
            etat = None
        if etat is not None and stat.S_ISLNK(etat.st_mode):
            os.unlink(nom, dir_fd=fd_parent)
            etat = None
        if etat is None:
            os.mkdir(nom, 0o700, dir_fd=fd_parent)
        try:
            fd = os.open(nom, DRAPEAUX, dir_fd=fd_parent)
        except OSError as e:
            if e.errno in (errno.ENOTDIR, errno.ELOOP):
                raise OSError(e.errno, f"{nom} n'est pas un dossier (ou un lien a été planté pendant l'opération)") from None
            raise
        try:
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.ENOTDIR, f"{nom} n'est pas un dossier")
            os.fchown(fd, compte.pw_uid, compte.pw_gid)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    finally:
        os.close(fd_parent)


def main(argv: "list[str]") -> int:
    if len(argv) not in (3, 4):
        print("usage : init_donnees.py PARENT NOM UTILISATEUR [MODE]", file=sys.stderr)
        return 2
    try:
        preparer(argv[0], argv[1], argv[2], int(argv[3], 8) if len(argv) == 4 else 0o750)
    except (OSError, KeyError, ValueError) as e:
        print(f"pilotage: dossier de données non préparé : {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
