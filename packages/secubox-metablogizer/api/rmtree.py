# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: metablogizer :: rmtree helper
CyberMind — https://cybermind.fr

Sites cloned from Gitea (sub-B of #49) carry a .git subtree whose pack files
are 0444 and whose directories may be 0500. Vanilla `shutil.rmtree` then
trips on `os.open(..., O_RDONLY, dir_fd=topfd)`. `force_remove` chmods the
offending entry to 0700 and retries the failing op.
"""
import os
import shutil
from pathlib import Path


def force_remove(path: Path) -> None:
    """`shutil.rmtree`, en relachant les droits qui bloquent — SANS toucher au parent.

    DEUX DEFAUTS CORRIGES ICI (#1041), et le premier a coupe la production.

    1. L'ancienne version faisait `os.chmod(parent, 0o700)`. Ce parent est
       PARTAGE par tous les sites : il perdait ses bits groupe et autres,
       `www-data` ne pouvait plus le traverser, et les 174 autres sites
       tombaient en 500. La suppression, elle, REUSSISSAIT — la panne
       n'apparaissait qu'au prochain acces a un site voisin, sans lien apparent
       avec l'action qui l'avait causee.

       On ne touche donc plus au parent. Si ses droits empechent vraiment de
       delier, la suppression echoue — franchement, et sans rien casser
       d'autre.

    2. Elle rejouait `func(entry)` a l'aveugle dans le gestionnaire d'erreur.
       Quand l'appel fautif est `os.open` (repertoire en 0o000), cette
       signature attend un argument de plus : `TypeError`, et la suppression
       s'arretait la.

    On relache donc les droits sur l'ARBRE VISE, puis on retente une fois.
    """
    def _relache(racine: Path) -> None:
        # `os.chmod` sur le repertoire AVANT d'y descendre : `os.walk` en mode
        # descendant le rend avant son contenu, ce qui permet d'ouvrir un
        # repertoire en 0o000 qu'on vient de rouvrir.
        try:
            os.chmod(racine, os.stat(racine).st_mode | 0o700)
        except OSError:
            pass
        for base, dossiers, fichiers in os.walk(racine):
            for nom in dossiers + fichiers:
                cible = os.path.join(base, nom)
                try:
                    # ON AJOUTE LES BITS MANQUANTS, on ne remplace pas le mode :
                    # retirer a autrui un acces qu'on n'a pas a lui retirer est
                    # exactement ce qui a casse la production.
                    os.chmod(cible, os.stat(cible).st_mode | 0o700)
                except OSError:
                    pass

    try:
        shutil.rmtree(path)
    except OSError:
        _relache(path)
        shutil.rmtree(path)
