# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: détection « TV/streamer probable » par comportement DNS (#1959).

Heuristique issue de DEUX cas réels (deux TV Android qui regardent le replay France TV, 2026-10-03) : une TV interroge régulièrement un serveur d'insertion
publicitaire (FreeWheel) ET au moins deux services de contenu ou de qualité vidéo. Les compteurs sont PAR JOUR (sans heure) : le seuil de requêtes tient lieu
de « plusieurs fenêtres ». Elle ne distingue PAS une TV d'un téléphone ou d'un ordinateur qui regarde le même replay : les garde-fous (plafonds, exclusions,
retrait en un clic) sont dans `dnstv_ajout`. Seuils de départ, à calibrer. Module pur : aucune entrée/sortie.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set

try:
    from . import dnstv
except ImportError:                                  # lancé hors paquet
    from api import dnstv

TYPES_CONTENU = ("contenu", "qualite_video")

# Seconde voie (#3771) : le service propre au SYSTÈME d'une TV connectée ou d'un boîtier TV. Seuls ces appareils l'interrogent (ni téléphone ni
# ordinateur), un direct sans insertion publicitaire suffit donc à reconnaître la TV. Liste réglable (`plateformes_tv` du TOML).
PLATEFORMES_TV = (
    "androidtvchannels-pa.googleapis.com",          # accueil Android TV / Google TV (Freebox Pop, Mini 4K, TV Sony, TCL, Philips…)
    "androidtv.prod.cloud.netflix.com",             # application Netflix d'Android TV
    "freebox.itc.proxad.net",                       # télémétrie des Freebox Player
    "lgtvsdp.com", "lgsmartad.com", "lgappstv.com",  # LG webOS
    "samsungcloudsolution.com", "samsungcloudsolution.net", "samsungotn.net", "samsungacr.com",  # Samsung Tizen
    "vidaahub.com",                                 # Hisense VIDAA
    "roku.com",                                     # Roku
)
MIN_PLATEFORME = 3


@dataclass
class Detection:
    source: str
    mac: str
    adresses: List[str]
    score: int
    preuve: str


def _suffixe(domaine: str, suffixes) -> bool:
    return any(domaine == s or domaine.endswith("." + s) for s in suffixes)


def detecter(compteurs, voisins, services, declencheurs, exclus: Set[str], min_declencheurs: int = 5, min_services: int = 2,
             plateformes=(), min_plateforme: int = MIN_PLATEFORME) -> List[Detection]:
    """`compteurs` : client -> domaine -> requêtes ; `voisins` : adresse -> MAC. Une source sans MAC connue n'est JAMAIS détectée (identité inconnue).
    Deux voies : insertion publicitaire + services vidéo (#1959), ou service du système d'une TV connectée (`plateformes`, #3771)."""
    par_mac: Dict[str, Dict[str, int]] = {}
    adresses: Dict[str, List[str]] = {}
    for client, doms in compteurs.items():
        mac = voisins.get(client)
        if not mac or client in exclus:
            continue
        adresses.setdefault(mac, []).append(client)
        cumul = par_mac.setdefault(mac, {})
        for d, n in doms.items():
            if dnstv.valider_domaine(d) == d:                       # un nom hostile n'est ni compté ni jamais recopié
                cumul[d] = cumul.get(d, 0) + int(n)
    out: List[Detection] = []
    for mac, doms in par_mac.items():
        dec = sum(n for d, n in doms.items() if _suffixe(d, declencheurs))
        orgs = sorted({org for d in doms for org, typ in [services.classer(d)] if typ in TYPES_CONTENU and org})
        if dec >= min_declencheurs and len(orgs) >= min_services:
            vus = sorted({s for d in doms for s in declencheurs if d == s or d.endswith("." + s)})
            preuve = f"{dec} requêtes vers {', '.join(vus)} ; services : {', '.join(orgs)}"[:120]
            out.append(Detection(mac, mac, sorted(adresses[mac]), min(100, dec + 10 * len(orgs)), preuve))
            continue
        cumul_tv = sum(n for d, n in doms.items() if _suffixe(d, plateformes))
        if plateformes and cumul_tv >= min_plateforme:
            vus = sorted({s for d in doms for s in plateformes if d == s or d.endswith("." + s)})
            preuve = f"système TV : {cumul_tv} requêtes vers {', '.join(vus)}"[:120]
            out.append(Detection(mac, mac, sorted(adresses[mac]), min(100, 40 + cumul_tv), preuve))
    return sorted(out, key=lambda x: (-x.score, x.mac))
