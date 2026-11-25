# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Pose les SRV de messagerie dans Unbound, seulement s'ils changent (#3941).

Bibliothèque commune secubox_unbound : checkconf, puis recharger_unbound (fast_reload : le DNS répond pendant la relecture),
ancien contenu remis au moindre refus. Le service Unbound lui-même n'est ni arrêté ni lancé.

Usage (postinst) : python3 -I unbound_srv.py <source> <destination> <actif|arrete>
"""
import sys
from pathlib import Path

from secubox_unbound import ErreurUnbound, SystemeUnbound, ecrire_verifier, poser_vue


class SystemeMail(SystemeUnbound):
    MODULE = "mail"


def poser(source: Path, destination: Path, actif: bool, systeme: SystemeUnbound | None = None) -> str:
    s = systeme or SystemeMail()
    texte = Path(source).read_text(encoding="utf-8")
    return (poser_vue if actif else ecrire_verifier)(Path(destination), texte, s)


if __name__ == "__main__":
    try:
        issue = poser(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3] == "actif")
    except (ErreurUnbound, OSError, UnicodeDecodeError) as e:
        print(f"secubox-mail: SRV Unbound non posés, configuration précédente gardée : {e}", file=sys.stderr)
        raise SystemExit(1) from e
    if issue != "inchange":
        print(f"secubox-mail: SRV Unbound : {issue}")
