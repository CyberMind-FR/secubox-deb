# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Posture du WAF : instantané `GET /waf/stats` (compteurs du jour), en faits seulement : contexte et rapprochement
des compteurs (`collecte.rapprocher`), jamais des événements d'attaque."""
from veille.sources import ErreurSource, Lot


class Posture:
    nom = "posture"
    intervalle_s = 900

    async def lire(self, client, curseur):
        r = await client.get("stats")
        if not isinstance(r, dict):
            raise ErreurSource("stats illisibles")
        compteurs = {k: v for k, v in (r.get("by_category") or {}).items()
                     if isinstance(k, str) and isinstance(v, int)} if isinstance(r.get("by_category"), dict) else {}
        return Lot([], curseur, {"stats": {"par_categorie": compteurs,
                                           "menaces_jour": r.get("threats_today") if isinstance(
                                               r.get("threats_today"), int) else None}})
