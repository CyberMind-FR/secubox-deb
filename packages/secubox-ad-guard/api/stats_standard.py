# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: métriques de la partie standard, d'après les compteurs DNS (#1963).

Le blocage réel vit dans le puits DNS (Unbound) : les compteurs de `secubox-adguard-dnsfeed` en sont la mesure. Un chiffre ABSENT est dit absent (« — » dans l'interface) :
jamais un zéro qui laisserait croire qu'il n'y a rien. Module pur : aucune entrée/sortie.
"""
from __future__ import annotations

from typing import Dict, Iterable, Set

try:
    from . import dnstv
except ImportError:                                  # lancé hors paquet
    from api import dnstv


def stats_dns(stats: dict, clients_du_jour: Iterable[str], voisins: Dict[str, str], exclus: Set[str]) -> dict:
    """stats : `Magasin.statistiques(depuis_jour=…)` ; clients_du_jour : adresses vues aujourd'hui. Un appareil = une MAC (IPv4 et IPv6 ensemble) ou, sans MAC connue, une adresse.
    La box elle-même n'est plus journalisée (#1959) : ses requêtes n'entrent pas dans les totaux."""
    requetes = int(stats.get("requetes", 0) or 0)
    bloquees = min(int((stats.get("par_decision") or {}).get("BLOCKED", 0) or 0), requetes)
    appareils = dnstv.regrouper_sources([c for c in clients_du_jour if c not in exclus], voisins)
    return {"dns_requetes_jour": requetes, "dns_bloquees_jour": bloquees, "dns_taux_blocage": round(100 * bloquees / requetes) if requetes else 0,
            "dns_appareils_jour": len(appareils), "dns_fenetre": "aujourd'hui (UTC)", "dns_lisible": True}
