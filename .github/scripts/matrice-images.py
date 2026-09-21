#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: matrice de construction d'images, dérivée des cartes.

POURQUOI CE SCRIPT EXISTE
-------------------------

La matrice de `build-image.yml` codait ses profils en dur — `["full", "isp"]`
— pour TOUTES les cartes. Et `build-image.sh` applique `--profile` de manière
INCONDITIONNELLE : il écrase le `SECUBOX_PROFILE` que la carte déclare dans
son `config.mk`.

Conséquence pour l'ESPRESSObin. Sa carte dit d'elle-même :

    SECUBOX_PROFILE=secubox-lite      # RAM limitée 1-2 GB
    SWAP_SIZE=512M

La CI répondait « full », soit 95 modules, sur un Armada 3720 dual-core
A53 avec 1 à 2 Go. C'est le scénario exact qui avait fait caler le rpi400 —
140 unités, 4 Go, aucun swap — sauf que l'ESPRESSObin a deux fois moins de
mémoire et quatre fois moins de cœurs.

LA CARTE SAIT CE QU'ELLE PEUT PORTER. Le `config.mk` est écrit en connaissant
le SoC, la RAM et le stockage ; la matrice, elle, ne connaissait rien. Écrire
`["full","isp"]` en YAML revenait à décider à la place de la carte, depuis
l'endroit le moins informé de la chaîne.

Ce script inverse la dépendance : il LIT les cartes et rend la matrice.
Ajoutez une carte demain avec son profil, elle apparaît sans que personne ne
touche au YAML.

CE QU'IL NE FAIT PAS
--------------------

Il ne supprime pas la possibilité de forcer un profil. Un opérateur qui veut
délibérément un `full` sur ESPRESSObin — pour mesurer, précisément, où ça
casse — garde `--profile full` en ligne de commande. On retire le choix par
DÉFAUT, pas le choix tout court : c'est la différence entre un garde-fou et
une interdiction.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

#: Profil bâti pour TOUTE carte, en plus de celui qu'elle déclare.
#:
#: `isp` est le socle routeur/FAI : il tient sur n'importe quelle carte du
#: parc, et c'est la seule image qui se compare d'une carte à l'autre. La
#: garder partout donne un point de repère quand un profil riche se met à
#: diverger.
PROFIL_SOCLE = "isp"

#: Profil retenu quand une carte ne déclare rien.
#:
#: `full` plutôt que `lite` — non par optimisme, mais parce que c'était le
#: comportement existant (`SECUBOX_PROFILE:-secubox-full` dans build-image.sh)
#: et qu'un script de matrice n'est pas l'endroit où changer silencieusement
#: ce que produisent les cartes qui marchent déjà.
PROFIL_DEFAUT = "full"

_RE_PROFIL = re.compile(r"^\s*SECUBOX_PROFILE\s*=\s*(\S+)", re.M)


def profil_de_carte(config_mk: Path) -> str | None:
    """Le profil que CETTE carte déclare, ou None.

    On lit le `config.mk` en texte plutôt que de le sourcer : le sourcer
    exécuterait du shell arbitraire depuis un job CI pour en extraire une
    seule variable, ce qui est un prix disproportionné.
    """
    try:
        texte = config_mk.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _RE_PROFIL.search(texte)
    if not m:
        return None
    # `secubox-lite` et `lite` désignent la même chose ; la matrice porte la
    # forme courte, qui est aussi celle qui nomme les images.
    return m.group(1).strip().removeprefix("secubox-") or None


def profils_pour(racine: Path, carte: str) -> list[str]:
    """Les profils à bâtir pour une carte, sans doublon et dans un ordre stable.

    L'ordre compte : deux exécutions doivent produire la même matrice, sinon
    les journaux de CI cessent de se comparer d'une fois sur l'autre.
    """
    declare = profil_de_carte(racine / "board" / carte / "config.mk") or PROFIL_DEFAUT
    profils = [declare]
    if PROFIL_SOCLE not in profils:
        profils.append(PROFIL_SOCLE)
    return profils


def matrice(racine: Path, cartes: list[str]) -> list[dict[str, str]]:
    return [
        {"board": c, "profile": p}
        for c in cartes
        for p in profils_pour(racine, c)
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--racine", default=".", help="racine du dépôt")
    ap.add_argument("--cartes", required=True,
                    help="cartes séparées par des virgules, ou 'defaut'")
    ap.add_argument("--defaut", default="mochabin,vm-x64,rpi400,espressobin-v7",
                    help="cartes bâties quand --cartes vaut 'defaut'")
    a = ap.parse_args()

    racine = Path(a.racine).resolve()
    brut = a.defaut if a.cartes.strip() in ("", "defaut", "all") else a.cartes
    cartes = [c.strip() for c in brut.split(",") if c.strip()]

    inconnues = [c for c in cartes if not (racine / "board" / c).is_dir()]
    if inconnues:
        # ÉCHOUER FORT. Une carte mal orthographiée qui produirait une matrice
        # vide ferait passer la CI au vert sans rien construire — un succès
        # qui ne prouve rien est pire qu'un échec.
        print("carte(s) inconnue(s) : %s" % ", ".join(inconnues), file=sys.stderr)
        return 2

    m = matrice(racine, cartes)
    if not m:
        print("matrice vide", file=sys.stderr)
        return 2

    print(json.dumps({"include": m}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
