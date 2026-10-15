# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: Premier Pas — REJOUER l'assistant de force (#2727)

Rouvre l'assistant d'une box que l'on croit configurée : retire le marqueur « fait », l'état du moteur, la demande d'application, la
proposition de la box maîtresse, la session distante et la trace de l'aide demandée. Le profil déjà rempli est GARDÉ (on reprend où l'on en
était) ; `vierge` l'efface aussi.

LOCAL ET ROOT SEULEMENT. Il n'existe volontairement aucune route distante pour cela : rouvrir l'assistant d'une box en service, c'est
rouvrir sa configuration, et seule une personne qui a déjà la main sur la box peut le demander.

Ne modifie ni le système ni le réseau : seule l'application de l'assistant, ensuite, le fait.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable, Dict

from . import moteur as M

journal = logging.getLogger("secubox.premier-pas")


class Refus(Exception):
    pass


def _dossier() -> Path:
    return Path(os.environ.get("PREMIER_PAS_DIR", "/var/lib/secubox/premier-pas"))


def rejouer(vierge: bool, relance: Callable[[], None], uid: int = None) -> Dict[str, object]:
    if (os.geteuid() if uid is None else uid) != 0:
        raise Refus("Rejouer l'assistant demande root : c'est un geste local sur la box.")
    d = _dossier()
    avait = M.MARQUEUR.exists()
    retires = []
    cibles = [M.MARQUEUR, M.ETAT, d / "demande", d / "proposition.json", d / "session-distante.json", M.MARQUEUR_AIDE]
    if vierge:
        cibles.append(d / "profil.toml")
    for c in cibles:
        try:
            c.unlink()
            retires.append(c.name)
        except FileNotFoundError:
            pass
    journal.warning("premier-pas : assistant rejoué de force (%s) ; retiré : %s", "profil effacé" if vierge else "profil gardé", ", ".join(retires) or "rien")
    relance()
    return {"marqueur": avait, "retires": retires, "vierge": vierge}
