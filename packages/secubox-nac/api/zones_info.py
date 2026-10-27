# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Comportement RÉEL de chaque zone du NAC, tel que les règles nftables le font (#2417).

Rien n'est déclaré qui ne soit appliqué : chaque ligne reprend une règle de
`nft/secubox-nac.nft` (un test le vérifie). Ce que le NAC ne fait PAS (puits DNS de
quarantaine, page de parking, zone de repli, Tor ou VPN par zone) est listé à part,
marqué indisponible : on ne le présente jamais comme une option active.

Tor et VPN existent bel et bien dans SecuBox, mais comme un choix du Toolbox PAR
CLIENT (niveau R0 à R3, tunnel WireGuard), pas comme une propriété d'une zone NAC.
L'analyse (DPI, DNS, Actor Intelligence) observe le trafic quelle que soit la zone.
"""
from __future__ import annotations

# valeurs : "oui" | "non" | "partiel" | "aucune restriction"
ZONES_COMPORTEMENT = {
    "lan": {
        "nom": "LAN principal", "ensemble": "lan_allowed",
        "internet": "oui", "lan": "oui", "box_dns_dhcp": "oui", "isolement": "aucun",
        "regles": ["Appartenance à l'ensemble lan_allowed : aucune règle de restriction."],
    },
    "lxc": {
        "nom": "Conteneurs LXC", "ensemble": "lxc_zone",
        "internet": "oui", "lan": "oui", "box_dns_dhcp": "oui", "isolement": "aucun (classement du pont br-lxc)",
        "regles": ["Zone de classement des conteneurs du pont br-lxc : aucune règle de restriction propre."],
    },
    "iot": {
        "nom": "IoT isolé", "ensemble": "iot_zone",
        "internet": "oui", "lan": "non", "box_dns_dhcp": "oui", "isolement": "LAN privé refusé",
        "regles": ["Vers 10.0.0.0/8, 172.16.0.0/12 et 192.168.0.0/16 : refusé (isolé du LAN).",
                   "Vers Internet : autorisé.",
                   "Depuis le LAN du mode routeur (br-lan) : vers la box, DNS et DHCP seulement."],
    },
    "guest": {
        "nom": "Invités", "ensemble": "guest_zone",
        "internet": "oui", "lan": "non", "box_dns_dhcp": "oui", "isolement": "LAN privé refusé",
        "regles": ["Vers 10.0.0.0/8, 172.16.0.0/12 et 192.168.0.0/16 : refusé (isolé du LAN).",
                   "Vers Internet : autorisé.",
                   "Depuis le LAN du mode routeur (br-lan) : vers la box, DNS et DHCP seulement."],
    },
    "quarantine": {
        "nom": "Quarantaine", "ensemble": "quarantine_zone",
        "internet": "non", "lan": "non", "box_dns_dhcp": "partiel", "isolement": "total",
        "regles": ["Vers la box : DNS (53) et DHCP (67, 68) seulement, le reste est refusé.",
                   "Vers tout autre réseau (transit) : refusé."],
    },
    "blocked": {
        "nom": "Bloqué", "ensemble": "blocked",
        "internet": "non", "lan": "non", "box_dns_dhcp": "non", "isolement": "total",
        "regles": ["Entrée vers la box, sortie et entrée en transit : refusées."],
    },
}

# Ce que fait l'analyse, indépendamment de la zone.
ANALYSE = [
    {"nom": "Analyse du trafic (DPI)", "etat": "actif", "portee": "tout le trafic vu par nDPId sur l'interface capturée, quelle que soit la zone"},
    {"nom": "Filtrage et suivi DNS (ad-guard)", "etat": "actif", "portee": "appareils qui interrogent le résolveur de la box"},
    {"nom": "Quarantaine automatique (Actor Intelligence)", "etat": "selon le mode", "portee": "isole un appareil sur preuves concordantes de deux capteurs au moins ; mode lisible sur la page"},
]

# Choix qui existent ailleurs dans SecuBox, mais PAS comme réglage de zone.
HORS_ZONE = [
    {"nom": "VPN (tunnel WireGuard) et Tor", "ou": "Toolbox : niveau R0 à R3 choisi par client, pas par zone"},
]

# Options que le NAC n'a pas : annoncées comme telles.
INDISPONIBLE = [
    {"nom": "Puits DNS (DNS hole) pour la quarantaine", "detail": "la quarantaine laisse passer DNS et DHCP vers la box mais ne détourne rien"},
    {"nom": "Parking / page de redirection de quarantaine", "detail": "aucune redirection : un appareil en quarantaine n'est simplement pas routé"},
    {"nom": "Zone de repli (fallback) automatique", "detail": "la zone par défaut d'un appareil neuf est la quarantaine (politique), pas un repli"},
    {"nom": "Tor ou VPN imposé par zone", "detail": "se règle par client dans le Toolbox"},
]


def comportements() -> dict:
    return {"zones": ZONES_COMPORTEMENT, "analyse": ANALYSE, "hors_zone": HORS_ZONE, "indisponible": INDISPONIBLE}
