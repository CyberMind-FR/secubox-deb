# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Sources de la veille V2 (#3720) : une par fichier. Protocole `Source` : `nom`, `intervalle_s`,
`async lire(client, curseur) -> Lot`. Les réponses de gk2 sont des données non fiables : une ligne illisible est
comptée et sautée, jamais fatale."""
from dataclasses import dataclass, field
from typing import Optional, Protocol

from veille import normaliser


@dataclass
class Lot:
    evenements: list = field(default_factory=list)
    curseur: Optional[str] = None
    faits: dict = field(default_factory=dict)


class Source(Protocol):
    nom: str
    intervalle_s: int

    async def lire(self, client, curseur: Optional[str]) -> Lot: ...


class ErreurSource(Exception):
    """Réponse de gk2 inutilisable (curseur `en_panne`, position gardée)."""


def liste(reponse, *cles) -> list:
    """Première liste trouvée sous l'une des clés (ou la réponse elle-même si c'est une liste)."""
    if isinstance(reponse, list):
        return reponse
    if not isinstance(reponse, dict):
        raise ErreurSource("réponse non objet")
    for c in cles:
        if isinstance(reponse.get(c), list):
            return reponse[c]
    return []


def normaliser_tous(nom, lignes, id_de, famille_defaut=None):
    """Normalise ; rend (evenements, ignorees)."""
    evts, ignorees = [], 0
    for brut in lignes:
        try:
            evts.append(normaliser.evenement(nom, brut, id_source=id_de(brut) if isinstance(brut, dict) else None,
                                             famille_defaut=famille_defaut))
        except ValueError:
            ignorees += 1
    return evts, ignorees


def toutes():
    """Les sources collectées par défaut (les essais des leurres viennent du flux des menaces)."""
    from veille.sources import (actord, bans, bans_actifs, blocs, campagnes, decisions, dns, garde, menaces,
                                posture, reevaluations)
    return [menaces.Menaces(), bans.Bans(), bans_actifs.BansActifs(), blocs.Blocs(), campagnes.Campagnes(),
            decisions.Decisions(), reevaluations.Reevaluations(), posture.Posture(), garde.Garde(),
            actord.Actord(), dns.Dns()]
