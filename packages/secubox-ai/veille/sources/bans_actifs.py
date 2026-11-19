# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Bans actifs : instantané `GET /waf/bans`. Curseur = adresses actives (JSON trié) ; apparition et disparition
rendues en événements par différence avec l'instantané précédent."""
import json

from veille import normaliser
from veille.sources import Lot, liste


class BansActifs:
    nom = "bans_actifs"
    intervalle_s = 300

    async def lire(self, client, curseur):
        r = await client.get("bans")
        actifs = {}
        for b in liste(r, "bans"):
            ip = normaliser.adresse(b.get("ip") if isinstance(b, dict) else b)[0]
            if ip:
                actifs[ip] = b if isinstance(b, dict) else {}
        try:
            avant = set(json.loads(curseur)) if curseur else None
        except ValueError:
            avant = None
        maintenant = int(client.horloge())
        evts = []
        if avant is not None:
            for ip, sens in [(i, "apparu") for i in sorted(set(actifs) - avant)] +                             [(i, "disparu") for i in sorted(avant - set(actifs))]:
                brut = dict(actifs.get(ip, {}), ip=ip, ts=maintenant, etat=sens)
                brut.setdefault("famille", "ban_actif")
                evts.append(normaliser.evenement(self.nom, brut, id_source=f"{sens}:{ip}:{maintenant}"))
        return Lot(evts, json.dumps(sorted(actifs)), {"actifs": len(actifs)})
