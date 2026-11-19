# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Bans posés par sbxwaf : `GET /waf/enforcement?depuis=<époque>` (les plus anciens d'abord). Curseur = `created_at`
maximal vu ; relire la même seconde est sans effet (empreinte). Identité = `id` de l'action."""
from veille.sources import Lot, liste, normaliser_tous

LIMITE = 1000
RATTRAPAGE_S = 86400


class Bans:
    nom = "bans"
    intervalle_s = 300

    async def lire(self, client, curseur):
        depuis = int(curseur) if curseur and curseur.isdigit() else int(client.horloge()) - RATTRAPAGE_S
        r = await client.get("enforcement", {"depuis": depuis, "limite": LIMITE})
        actions = liste(r, "actions")
        evts, ignorees = normaliser_tous(self.nom, actions, lambda a: a.get("id"), "ban")
        vus = [a.get("created_at") for a in actions if isinstance(a, dict) and isinstance(a.get("created_at"), int)]
        return Lot(evts, str(max(vus + [depuis])), {"ignorees": ignorees, "complet": bool(r.get("complet", True))})
