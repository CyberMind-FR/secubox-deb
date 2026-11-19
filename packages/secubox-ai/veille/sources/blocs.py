# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Blocs /24 et gestes de l'IA en cours : instantané `GET /waf/ai/etat` → `{actifs:[{id, cible, fin, mode}]}`.
Rendu en faits (table `blocs`), jamais en événements."""
from veille import normaliser
from veille.sources import Lot, liste


class Blocs:
    nom = "blocs"
    intervalle_s = 300

    async def lire(self, client, curseur):
        blocs = []
        for a in liste(await client.get("ai_etat"), "actifs"):
            if not isinstance(a, dict):
                continue
            cible = normaliser.texte(a.get("cible"), 64) or ""
            if not cible.endswith("/24"):
                continue
            bloc = normaliser.adresse(cible)[1]
            if bloc:
                blocs.append({"bloc24": bloc, "banni_jusqua": normaliser.utc(a.get("fin")),
                              "origine": normaliser.texte(a.get("mode"), 32) or "ai"})
        return Lot([], None, {"blocs": blocs})
