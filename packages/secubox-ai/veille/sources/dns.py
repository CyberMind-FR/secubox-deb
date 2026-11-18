# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Alertes DNS d'ad-guard (dnsguard) : premier appel `depuis=<RFC 3339>`, ensuite `apres=<suivant>` (curseur opaque
`<époque>:<rang>`)."""
import re
from datetime import datetime, timezone

from veille import normaliser
from veille.sources import ErreurSource, Lot, liste, normaliser_tous

RATTRAPAGE_S = 86400
_CURSEUR = re.compile(r"^[0-9]{1,10}:[0-9]{1,9}$")


class Dns:
    nom = "dns"
    intervalle_s = 120

    async def lire(self, client, curseur):
        if curseur and _CURSEUR.match(curseur):
            params = {"apres": curseur}
        else:
            depuis = datetime.fromtimestamp(client.horloge() - RATTRAPAGE_S, timezone.utc)
            params = {"depuis": normaliser.rfc3339(depuis)}
        r = await client.get("dns_alertes", params)
        if not isinstance(r, dict):
            raise ErreurSource("réponse non objet")
        evts, ignorees = normaliser_tous(self.nom, liste(r, "alertes"),
                                         lambda a: str(a.get("id")) if a.get("id") is not None else None, "dns")
        suivant = r.get("suivant")
        return Lot(evts, suivant if isinstance(suivant, str) and _CURSEUR.match(suivant) else curseur,
                   {"ignorees": ignorees, "trou": bool(r.get("trou"))})
