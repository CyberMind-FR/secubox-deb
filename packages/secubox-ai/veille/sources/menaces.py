# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Menaces (sbxwaf + sbx-authwatch) : `GET /waf/menaces/flux?depuis=<inode:octet>` → `{lignes:[{position, ligne}],
suivant, rotation, trou}`. Identité d'un événement = position `inode:octet` (garde les doublons réels)."""
import json

from veille import normaliser
from veille.sources import ErreurSource, Lot, leurres

MAX_LIGNES = 500


class Menaces:
    nom = "menaces"
    intervalle_s = 30

    async def lire(self, client, curseur):
        r = await client.get("menaces_flux", {"depuis": curseur, "max": MAX_LIGNES})
        if not isinstance(r, dict) or not isinstance(r.get("lignes"), list):
            raise ErreurSource("flux illisible")
        evts, ignorees = [], 0
        for item in r["lignes"]:
            try:
                brut = item.get("ligne")
                if isinstance(brut, str):
                    brut = json.loads(brut[:65536])
                e = normaliser.evenement(self.nom, brut, id_source=item.get("position"))
            except (ValueError, AttributeError, TypeError):
                ignorees += 1
                continue
            essais = leurres.essais(brut)
            if essais:
                e.attributs["essais"] = essais
            evts.append(e)
        suivant = r.get("suivant")
        return Lot(evts, suivant if isinstance(suivant, str) and suivant else curseur,
                   {"ignorees": ignorees, "trou": bool(r.get("trou")), "rotation": bool(r.get("rotation"))})
