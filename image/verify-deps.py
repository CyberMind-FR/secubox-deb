#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dépendances manquantes d'une image (#2495) : tout paquet secubox-* installé dont un `Depends` n'est pas présent.

    python3 image/verify-deps.py <racine de l'image> [préfixe, défaut « secubox- »]

`dpkg -i --force-depends` installe un paquet même si ses dépendances manquent, et `verify-profile.sh` ne regarde que la présence du profil et l'état des paquets
secubox : une image sans systemd-timesyncd, python3-cryptography ou lxc passait donc tous les contrôles et ne montrait son défaut qu'au premier démarrage (premier
pas arrêté à l'étape Horloge). Ici on lit le fichier d'état dpkg de l'image (aucun chroot) : une alternative `a | b` est satisfaite par l'une ou l'autre, un paquet virtuel par
un `Provides`. Les contraintes de version ne sont pas vérifiées (dpkg s'en charge à l'installation) : seule la PRÉSENCE. Code 1 et liste si quelque chose manque."""
import re
import sys
from pathlib import Path


def lire_etat(chemin: Path):
    """{paquet: depends} des paquets réellement installés, et l'ensemble des noms fournis (paquets + Provides)."""
    txt = chemin.read_text(encoding="utf-8", errors="replace")
    installes, fournis = {}, set()
    for blk in txt.split("\n\n"):
        m = re.search(r"^Package: (\S+)", blk, re.M)
        st = re.search(r"^Status: (.*)", blk, re.M)
        if not m or not st:
            continue
        etat = st.group(1).split()
        if not etat or etat[-1] not in ("installed", "triggers-pending"):
            continue                                  # absent, supprimé ou à moitié installé : pas un fournisseur fiable (verify-profile.sh s'occupe des moitiés)
        fournis.add(m.group(1))
        d = re.search(r"^Depends: (.*(?:\n .*)*)", blk, re.M)
        installes[m.group(1)] = d.group(1).replace("\n", " ") if d else ""
        for p in re.finditer(r"^Provides: (.*(?:\n .*)*)", blk, re.M):
            for x in p.group(1).replace("\n", " ").split(","):
                nom = x.strip().split(" ")[0].split(":")[0]
                if nom:
                    fournis.add(nom)
    return installes, fournis


def manques(chemin: Path, prefixe: str = "secubox-") -> dict:
    installes, fournis = lire_etat(chemin)
    out = {}
    for nom, deps in sorted(installes.items()):
        if not nom.startswith(prefixe) or not deps.strip():
            continue
        for groupe in deps.split(","):
            alts = [re.sub(r"\(.*?\)|\[.*?\]|<.*?>", "", a).strip().split(":")[0] for a in groupe.split("|") if a.strip()]
            alts = [a for a in alts if a]
            if alts and not any(a in fournis for a in alts):
                out.setdefault(nom, []).append(" | ".join(alts))
    return out


def main(argv) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    racine = Path(argv[0])
    etat = racine / "var/lib/dpkg/status"
    if not etat.is_file():
        print(f"verify-deps : {etat} introuvable", file=sys.stderr)
        return 2
    m = manques(etat, argv[1] if len(argv) > 1 else "secubox-")
    if not m:
        print("verify-deps : toutes les dépendances des paquets secubox-* sont présentes")
        return 0
    print(f"IMAGE INCOMPLÈTE : {len(m)} paquet(s) secubox-* avec des dépendances absentes :", file=sys.stderr)
    for nom, l in m.items():
        print(f"  - {nom} : {', '.join(l)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
