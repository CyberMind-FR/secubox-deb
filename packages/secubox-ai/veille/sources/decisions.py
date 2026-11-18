# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Décisions de ban par source : instantané `GET /waf/decisions` → `{genere_le, decisions}`. Identité =
(`source`, `target`, `genere_le`)."""
from veille.sources import Lot, liste, normaliser_tous


class Decisions:
    nom = "decisions"
    intervalle_s = 300

    async def lire(self, client, curseur):
        r = await client.get("decisions")
        genere = r.get("genere_le") if isinstance(r, dict) else None
        lignes = [dict(d, genere_le=genere) for d in liste(r, "decisions") if isinstance(d, dict)]
        evts, ignorees = normaliser_tous(self.nom, lignes,
                                         lambda d: f"{d.get('source')}:{d.get('target')}:{d.get('genere_le')}",
                                         "decision")
        return Lot(evts, str(genere) if genere is not None else curseur, {"ignorees": ignorees})
