#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SBX OS :: AUCUN ACCENT GRAVE DANS UN GABARIT (#1357).

LA MÊME FAUTE TROIS FOIS DANS LA MÊME JOURNÉE. Les composants portent leur CSS
dans un template literal. Notre convention d'écriture cite les termes techniques
entre accents graves — et chacun FERME la chaîne. Le module devient
syntaxiquement invalide, donc n'est jamais chargé, et le symptôme n'a aucun
rapport avec la cause : un bureau vide, puis un écran noir, puis une pastille
rouge sur chaque vignette.

UNE CONVENTION QUI SE RETOURNE CONTRE SOI NE SE CORRIGE PAS PAR L'ATTENTION.
Elle se corrige par un contrôle, et celui-ci tourne à la construction du paquet.
Employer des guillemets français à l'intérieur d'un gabarit : ils disent la même
chose et ne ferment rien.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def fautes(source: str) -> list[str]:
    """Les lignes portant un accent grave DANS un gabarit."""
    trouve: list[str] = []
    for m in re.finditer(r"innerHTML\s*=\s*`", source):
        debut = m.end()
        fin = source.find("`;", debut)
        if fin < 0:
            continue
        for ligne in source[debut:fin].split("\n"):
            if "`" in ligne:
                trouve.append(ligne.strip()[:70])
    return trouve


def main() -> int:
    racine = Path(__file__).resolve().parents[1] / "www"
    mauvais = 0
    for f in sorted(racine.rglob("*.js")):
        for ligne in fautes(f.read_text(encoding="utf-8")):
            print(f"{f.relative_to(racine)} : accent grave dans un gabarit — {ligne}",
                  file=sys.stderr)
            mauvais += 1
    if mauvais:
        print(f"{mauvais} accent(s) grave(s) ferment un gabarit. "
              "Employer des guillemets français.", file=sys.stderr)
        return 1
    print("gabarits : aucun accent grave")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
