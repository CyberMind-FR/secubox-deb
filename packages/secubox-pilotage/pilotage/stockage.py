# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: contrat de stockage consommé par le canal (#3126)

Le canal ne connaît que ce protocole ; la version SQLite (Task 9) s'y conforme. Les valeurs reçues d'une box sont déjà bornées
et de forme vérifiée quand elles arrivent ici. Les méthodes sont synchrones : le canal les appelle hors de la boucle (to_thread).
"""
from __future__ import annotations

from typing import Protocol

from .identite import Box


class StockageCanal(Protocol):
    def vu(self, box: Box, infos: dict) -> None:
        """Signe de vie : bonjour (infos = agent_version, boot_id, modele) ou sondage (infos = {})."""

    def notification(self, box: Box, evenement: dict) -> None:
        """Un événement NOTIFY remis par la box (le contenu de `body.event`)."""

    def resultat(self, box: Box, msg_id: str, reponse: dict) -> None:
        """Une réponse livrée à une requête émise pour cette box (`{msg_id, type, body}`)."""


class StockageMemoire:
    """Implémentation en mémoire, pour les tests."""

    def __init__(self) -> None:
        self.vus: list = []
        self.notifications: list = []
        self.resultats: list = []

    def vu(self, box: Box, infos: dict) -> None:
        self.vus.append((box, dict(infos)))

    def notification(self, box: Box, evenement: dict) -> None:
        self.notifications.append((box, evenement))

    def resultat(self, box: Box, msg_id: str, reponse: dict) -> None:
        self.resultats.append((box, msg_id, reponse))
