# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Aucune règle sudoers livrée n'accorde une commande lxc-* (#1785).

`sudo lxc-start -f <configuration>` exécute les crochets de la configuration
en root sur l'hôte ; `sudo lxc-attach` donne root dans tout conteneur. Les
comptes de service passent par /usr/sbin/secubox-lxcctl (secubox-core), qui
n'admet qu'une liste fermée d'options.
"""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
LXC = re.compile(r"/usr/s?bin/lxc-[a-z-]+")


def _fichiers_sudoers():
    # « sudoers » dans le NOM ou dans un RÉPERTOIRE (debian/sudoers.d/secubox-vm).
    for f in sorted(RACINE.glob("packages/**/*")):
        rel = f.relative_to(RACINE)
        if f.is_file() and ".git" not in rel.parts and "sudoers" in str(rel) \
                and f.suffix not in (".py", ".md"):
            yield f


def test_aucune_regle_sudoers_n_accorde_une_commande_lxc():
    fautifs = []
    for f in _fichiers_sudoers():
        for n, ligne in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if ligne.lstrip().startswith("#") or "NOPASSWD" not in ligne:
                continue
            if LXC.search(ligne):
                fautifs.append(f"{f.relative_to(RACINE)}:{n}: {ligne.strip()}")
    assert not fautifs, "passer par /usr/sbin/secubox-lxcctl :\n" + "\n".join(fautifs)


def test_le_passage_etroit_existe():
    regle = RACINE / "packages/secubox-core/sudoers.d/secubox-lxcctl"
    assert "NOPASSWD: /usr/sbin/secubox-lxcctl" in regle.read_text()
