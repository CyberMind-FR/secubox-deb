# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Propositions d'actord : `GET /waf/actord/propositions`. `available:false` + `motif` : `absent` = source vide
normale ; `illisible` / `invalide` = panne (curseur `en_panne`)."""
from veille.sources import ErreurSource, Lot, normaliser_tous


class Actord:
    nom = "actord"
    intervalle_s = 300

    async def lire(self, client, curseur):
        r = await client.get("actord")
        if not isinstance(r, dict):
            raise ErreurSource("réponse non objet")
        if not r.get("available"):
            motif = r.get("motif")
            if motif == "absent":
                return Lot([], curseur, {"motif": "absent"})
            raise ErreurSource(f"actord {str(motif)[:32]}")
        p = r.get("propositions")
        lignes = p if isinstance(p, list) else (p.get("propositions") if isinstance(p, dict) else None) or []
        evts, ignorees = normaliser_tous(self.nom, [x for x in lignes if isinstance(x, dict)],
                                         lambda x: str(x.get("id")) if x.get("id") is not None else None, "actord")
        return Lot(evts, curseur, {"ignorees": ignorees})
