#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: image — selection des .deb selon le profil
CyberMind — https://cybermind.fr

POURQUOI CE SCRIPT EXISTE. `build-rpi-usb.sh` copiait TOUS les .deb trouves :

    cp "${DEBS_DIR}"/secubox-*_all.deb   "${ROOTFS}/tmp/secubox-debs/"
    cp "${DEBS_DIR}"/secubox-*_arm64.deb "${ROOTFS}/tmp/secubox-debs/"

Le profil ne servait donc qu'a nommer le fichier et choisir sa taille : `isp`
et `full` produisaient la MEME image. Mesure a l'appui, deux artefacts du meme
run differaient de 27 607 octets sur 676 Mo — 0,004 %, le bruit des
horodatages. Consequence sur un rpi400 (4 Go, sans swap) : 175 paquets
installes, 140 unites levees au demarrage dont 118 interpretes Python
persistants, soit 4,6 a 9,2 Go demandes. La machine se figeait — un shell
s'ouvrait, puis tout fork() restait bloque (#1308).

CE QU'IL FAIT. Il part du meta-paquet `secubox-<profil>` et suit ses `Depends`
de proche en proche, ne retenant que les paquets SecuBox atteignables. Les
dependances non-SecuBox ne sont pas copiees : elles viennent d'apt, comme
avant.

Il ECHOUE si le meta-paquet manque, plutot que de retomber sur « tout
copier ». Produire une image `isp` au contenu `full` est precisement le
mensonge que ce script existe pour empecher, et un avertissement de plus dans
un journal de 1 700 lignes n'aurait protege personne.

DEUX FORMES DE PROFIL. L'argument <profil> est soit un NOM — le meta-paquet
`secubox-<nom>` fait alors autorite — soit un CHEMIN vers un fichier listant
les modules voulus, un par ligne (le prefixe `secubox-` est optionnel, les
lignes vides et les commentaires `#` sont ignores). La seconde forme permet
de composer un profil a l'installation sans qu'un meta-paquet existe pour
lui : on donne la liste des modules, la fermeture transitive de leurs
Depends fait le reste.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

# Un champ Depends se lit : « a, b (>= 1.2), c | d ». On decoupe sur les
# virgules (groupes), puis sur les barres (alternatives), et on jette les
# contraintes de version entre parentheses.
_VERSION = re.compile(r"\([^)]*\)")


def noms_depends(champ: str) -> set[str]:
    """Tous les noms de paquets cites par un champ Depends, alternatives
    comprises. On garde TOUTES les alternatives plutot que la premiere : si
    l'une d'elles est un module SecuBox, le profil la veut."""
    noms: set[str] = set()
    for groupe in champ.split(","):
        for alt in groupe.split("|"):
            nom = _VERSION.sub("", alt).strip().split(":")[0]
            if nom:
                noms.add(nom)
    return noms


def champ(deb: Path, nom: str) -> str:
    try:
        return subprocess.run(
            ["dpkg-deb", "-f", str(deb), nom],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return ""


def main(argv: list[str]) -> int:
    if len(argv) not in (4, 5):
        print(f"usage: {argv[0]} <repertoire-debs> <profil> <destination> [arch]",
              file=sys.stderr)
        return 2
    src, profil, dest = Path(argv[1]), argv[2], Path(argv[3])
    arch = argv[4] if len(argv) == 5 else None

    debs = sorted(src.glob("secubox-*.deb"))
    if not debs:
        print(f"[profil] aucun .deb SecuBox dans {src}", file=sys.stderr)
        return 1

    # FILTRER L'ARCHITECTURE AVANT D'INDEXER. Un meme paquet peut exister en
    # _amd64 ET _arm64 dans le meme repertoire ; sans ce filtre l'index garde
    # celui qui arrive en dernier dans l'ordre alphabetique — donc « amd64 »
    # gagne toujours, y compris pour une image arm64. Le .deb serait installe
    # par `dpkg -i --force-*`, qui ne protege de rien ici, et l'image
    # emporterait des binaires de la mauvaise architecture.
    if arch:
        debs = [d for d in debs
                if d.name.endswith(f"_{arch}.deb") or d.name.endswith("_all.deb")]
        if not debs:
            print(f"[profil] aucun .deb en {arch} ni en all dans {src}", file=sys.stderr)
            return 1

    # Index paquet -> (fichier, depends). Quand plusieurs versions du meme
    # paquet trainent, la derniere en ordre alphabetique gagne — c'est le
    # comportement qu'avait deja le `cp` en vrac.
    index: dict[str, tuple[Path, set[str]]] = {}
    for d in debs:
        p = champ(d, "Package")
        if p:
            index[p] = (d, noms_depends(champ(d, "Depends")))

    # Forme « fichier » : une liste de modules composee a la main. On la
    # reconnait a l'existence du chemin, jamais a sa syntaxe — un profil
    # nomme ne contient pas de separateur, donc aucune ambiguite en pratique.
    chemin = Path(profil)
    if chemin.is_file():
        racines: list[str] = []
        for ligne in chemin.read_text(encoding="utf-8").splitlines():
            ligne = ligne.split("#", 1)[0].strip()
            if not ligne:
                continue
            racines.append(ligne if ligne.startswith("secubox-") else f"secubox-{ligne}")
        inconnus = [r for r in racines if r not in index]
        if inconnus:
            print(f"[profil] modules inconnus dans {chemin} : {', '.join(inconnus)}", file=sys.stderr)
            return 1
        if not racines:
            print(f"[profil] {chemin} ne liste aucun module.", file=sys.stderr)
            return 1
        return _copier(index, racines, dest, f"liste {chemin.name}")

    meta = f"secubox-{profil}"
    if meta not in index:
        print(f"[profil] meta-paquet {meta} introuvable dans {src}.", file=sys.stderr)
        print("[profil] Sans lui le profil ne peut pas etre honore, et produire", file=sys.stderr)
        print("[profil] une image d'un profil au contenu d'un autre serait un", file=sys.stderr)
        print(f"[profil] mensonge. Disponibles : {', '.join(sorted(k for k in index if k.startswith('secubox-')) [:6])}...", file=sys.stderr)
        return 1

    return _copier(index, [meta], dest, profil)


def _copier(index: dict[str, tuple[Path, set[str]]], racines: list[str],
            dest: Path, etiquette: str) -> int:
    """Fermeture transitive depuis les racines, puis copie."""
    vus: set[str] = set()
    pile = list(racines)
    while pile:
        p = pile.pop()
        if p in vus or p not in index:
            continue
        vus.add(p)
        pile.extend(n for n in index[p][1] if n.startswith("secubox-"))

    dest.mkdir(parents=True, exist_ok=True)
    for p in sorted(vus):
        shutil.copy2(index[p][0], dest / index[p][0].name)

    ecartes = len(index) - len(vus)
    print(f"[profil] {etiquette} : {len(vus)} paquet(s) retenu(s), "
          f"{ecartes} ecarte(s) sur {len(index)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
