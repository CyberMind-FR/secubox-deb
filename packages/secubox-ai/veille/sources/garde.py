# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Garde (secubox-garde) : `GET /api/v1/garde/historique?heures=24` → `{lignes:[{id?, menace, debut, …}]}`.
Famille = `menace` telle que la garde la nomme ; identité = `id` ou (menace, début, nom)."""
from veille.sources import Lot, liste, normaliser_tous

HEURES = 24


class Garde:
    nom = "garde"
    intervalle_s = 300

    async def lire(self, client, curseur):
        r = await client.get("garde_historique", {"heures": HEURES})
        evts, ignorees = normaliser_tous(
            self.nom, liste(r, "lignes"),
            lambda x: str(x.get("id")) if x.get("id") is not None else f"{x.get('menace')}:{x.get('debut')}:{x.get('nom')}",
            "garde")
        return Lot(evts, curseur, {"ignorees": ignorees,
                                   "session_requise": bool(r.get("session_requise")) if isinstance(r, dict) else False})
