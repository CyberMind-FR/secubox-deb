# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Reconstruit la table des clients depuis l'activité réelle du tunnel (#2413).

Une ligne de `clients` n'est créée que par un consentement, un changement de
niveau ou la génération d'un profil WireGuard. Après « Oublier tous », rien ne la
recréait : la table restait vide alors que des pairs échangeaient du trafic. Ici,
tout pair WireGuard dont la poignée de main est récente (re)devient un client, au
niveau R3 par défaut ; le niveau d'un client déjà connu n'est jamais touché.
"""
from __future__ import annotations

import logging

from . import store, wg

log = logging.getLogger("secubox.toolbox")

FENETRE_S = 900   # un pair vu dans les 15 dernières minutes est un client actif
PERIODE_S = 60


def synchroniser(fenetre_s: int = FENETRE_S) -> int:
    """Rend le nombre de lignes créées."""
    n = 0
    for h, (ip, ts) in wg.wg_actifs(fenetre_s).items():
        try:
            if store.ensure_client(h, ip, "r3", vu=ts):
                n += 1
        except Exception as e:  # une ligne en échec ne doit pas arrêter les autres
            log.warning("sync client %s: %s", h, e)
    if n:
        log.info("clients recrees depuis le tunnel WireGuard : %d", n)
    return n
