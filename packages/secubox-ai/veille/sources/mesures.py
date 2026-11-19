# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Mesures Actor Intelligence : `GET /waf/mesures?depuis=<époque>` → `{mesures:[{actor, ip, ts, decision, …}]}`.

Seuls `actor`, `ip`, `ts` (époque UTC) et `decision` sont gardés (texte tronqué) : ils rattachent une adresse à un
acteur d'actord pour les dossiers (#3795). Une mesure n'est ni une observation ni une preuve : marquée
`exclu_correlation = "mesure"`. Curseur = `ts` maximal vu ; relire la même seconde est sans effet (empreinte)."""
from veille import normaliser
from veille.sources import Lot, liste, normaliser_tous

LIMITE = 2000
RATTRAPAGE_S = 86400


def _garder(m):
    return {"ts": m.get("ts"), "actor": normaliser.texte(m.get("actor"), 32), "ip": normaliser.texte(m.get("ip"), 64),
            "decision": normaliser.texte(m.get("decision"), 32), "exclu_correlation": "mesure"}


class Mesures:
    nom = "mesures"
    intervalle_s = 300

    async def lire(self, client, curseur):
        depuis = int(curseur) if curseur and curseur.isdigit() else int(client.horloge()) - RATTRAPAGE_S
        r = await client.get("mesures", {"depuis": depuis, "limite": LIMITE})
        lignes = [_garder(m) for m in liste(r, "mesures") if isinstance(m, dict)]
        evts, ignorees = normaliser_tous(self.nom, lignes, lambda m: f"{m.get('actor')}:{m.get('ip')}:{m.get('ts')}",
                                         "mesure")
        vus = [m["ts"] for m in lignes if isinstance(m["ts"], int) and not isinstance(m["ts"], bool)]
        return Lot(evts, str(max(vus + [depuis])), {"ignorees": ignorees, "complet": bool(r.get("complet", True))
                                                    if isinstance(r, dict) else True})
