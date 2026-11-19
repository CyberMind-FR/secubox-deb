# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Leurres de service (#3728) : les `essais` portés par les lignes de sbx-authwatch du flux des menaces.

Pas de route propre : la source `menaces` appelle `essais()` sur chaque ligne. gk2 ne rend jamais le mot de passe
(`mot_de_passe_hmac`, peut être null, et `mot_de_passe_longueur`) ; on ne garde que ces trois champs, tronqués."""
from veille.normaliser import texte

ESSAIS_MAX = 32


def essais(brut: dict) -> list:
    out = []
    for e in brut.get("essais") or [] if isinstance(brut.get("essais"), list) else []:
        if not isinstance(e, dict):
            continue
        longueur = e.get("mot_de_passe_longueur")
        out.append({"compte": texte(e.get("compte"), 64),
                    "mot_de_passe_hmac": texte(e.get("mot_de_passe_hmac"), 64),
                    "mot_de_passe_longueur": longueur if isinstance(longueur, int) and not isinstance(longueur, bool)
                    else None})
        if len(out) >= ESSAIS_MAX:
            break
    return out
