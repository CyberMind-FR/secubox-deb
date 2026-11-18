# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Réévaluations des bans : `GET /waf/reevaluations?limite=1000`. Curseur = `ts` maximal vu ; identité =
(ts, ip, decision)."""
from veille.sources import Lot, liste, normaliser_tous

LIMITE = 1000


class Reevaluations:
    nom = "reevaluations"
    intervalle_s = 300

    async def lire(self, client, curseur):
        borne = int(curseur) if curseur and curseur.isdigit() else 0
        lignes = [x for x in liste(await client.get("reevaluations", {"limite": LIMITE}), "reevaluations")
                  if isinstance(x, dict) and isinstance(x.get("ts"), int) and x["ts"] >= borne]
        evts, ignorees = normaliser_tous(self.nom, lignes,
                                         lambda x: f"{x.get('ts')}:{x.get('ip')}:{x.get('decision')}", "reevaluation")
        for e in evts:
            e.sous_famille = e.sous_famille or e.attributs.get("decision")
        return Lot(evts, str(max([x["ts"] for x in lignes] + [borne])), {"ignorees": ignorees})
