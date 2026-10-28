#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: gen-empreintes-livrees — empreintes de toutes les versions LIVRÉES des profils de référence (#3218).

Lit l'historique git de packages/secubox-profiles/profiles/*.toml et écrit profiles/empreintes-livrees.txt
(« <sha256>  <nom>.toml », format de sha256sum). Le postinst (scripts/maj-references.py) y reconnaît une copie de
/etc/secubox/profiles que l'opérateur n'a pas modifiée, et la remplace par la nouvelle référence.

À relancer après toute modification d'un profil de référence (le test test_references_3218 le rappelle) :
    python3 packages/secubox-profiles/scripts/gen-empreintes-livrees.py
Outil de développement : il exige git et n'est pas appelé à la construction du paquet."""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
PROFILS = PKG / "profiles"
SORTIE = PROFILS / "empreintes-livrees.txt"
ENTETE = ("# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
          "# Empreintes (sha256) des versions LIVRÉES des profils de référence, tirées de l'historique git (#3218).\n"
          "# Générées par scripts/gen-empreintes-livrees.py ; lues par scripts/maj-references.py (postinst).\n")


def _git(*args: str, cwd: Path = PKG) -> bytes:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True, timeout=60).stdout


def empreintes() -> set[str]:
    out: set[str] = set()
    racine = Path(_git("rev-parse", "--show-toplevel").decode().strip()).resolve()
    for f in sorted(PROFILS.glob("*.toml")):
        rel = f.resolve().relative_to(racine).as_posix()            # chemins git relatifs à la RACINE du dépôt
        out.add(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}")           # la version de l'arbre de travail
        for rev in _git("log", "--format=%H", "--", rel, cwd=racine).decode().split():
            try:
                contenu = _git("show", f"{rev}:{rel}", cwd=racine)
            except subprocess.CalledProcessError:
                continue                                                               # fichier absent à ce commit
            out.add(f"{hashlib.sha256(contenu).hexdigest()}  {f.name}")
    return out


def main() -> int:
    lignes = sorted(empreintes(), key=lambda x: (x.split("  ")[1], x))
    SORTIE.write_text(ENTETE + "\n".join(lignes) + "\n", encoding="utf-8")
    print(f"[empreintes] {len(lignes)} versions livrées -> {SORTIE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
