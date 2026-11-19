# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Campagnes du WAF : instantané `GET /waf/campaigns`, faits repris tels quels (table `campagnes`, clé signature)."""
from veille import normaliser
from veille.sources import Lot, liste

LIMITE = 1000


def _entier(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


class Campagnes:
    nom = "campagnes"
    intervalle_s = 300

    async def lire(self, client, curseur):
        faites = []
        for c in liste(await client.get("campaigns", {"limite": LIMITE}), "campagnes"):
            if not isinstance(c, dict) or not normaliser.texte(c.get("signature"), 64):
                continue
            faites.append({"id": normaliser.texte(c.get("signature"), 64), "outil": normaliser.texte(c.get("outil"), 64),
                           "attaquants": _entier(c.get("attaquants")), "sondes": _entier(c.get("sondes")),
                           "haute_valeur": _entier(c.get("haute_valeur")),
                           "premiere_vue": normaliser.utc(c.get("premiere_vue")),
                           "derniere_vue": normaliser.utc(c.get("derniere_vue"))})
        return Lot([], None, {"campagnes": faites})
