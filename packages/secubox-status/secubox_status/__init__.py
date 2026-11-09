# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox Status Live v2 (#3595, jalon 1 #3605) : moteur local de supervision, lecture seule.

Le collecteur LIT les caches existants (santé des vhosts et des modules, relevé de validation des profils) et
`/proc` ; il ne recalcule rien et ne lance aucune commande. Une mesure absente ou périmée vaut `unknown`,
jamais `operational` ni `outage`.
"""

SCHEMA_RELEVE = "secubox.status.snapshot"
SCHEMA_PUBLIC = "secubox.status.public"
VERSION = 2

ETATS = ("operational", "degraded", "outage", "maintenance", "unknown")
