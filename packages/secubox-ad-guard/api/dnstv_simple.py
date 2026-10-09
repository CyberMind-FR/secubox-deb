# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: logique pure du panneau simplifié (#2174).

Trois choses, sans accès réseau ni disque (les routes les branchent) :
 - regrouper les adresses d'un même appareil en une carte (nom, protégé ou non, état lisible) ;
 - repérer les noms qui « ressemblent à une pub » parmi ce que l'appareil a obtenu récemment ;
 - vérifier, après application, que le drop-in Unbound reflète bien l'état demandé (un changement perdu se voit au lieu de passer sous silence).
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set

try:
    from . import dnstv
except ImportError:                                  # lancé hors paquet
    from api import dnstv

SUSPECTS_MAX = 20
# Un mot entier dans un des libellés du nom (« ads-metrics.tvchaine.example » : « ads », « metrics »), jamais une sous-chaîne (« loads », « pads »).
MOTS_PUB = {
    "ad": "contient « ad »", "ads": "contient « ads »", "adserver": "serveur de pub", "adserving": "serveur de pub", "adservice": "service de pub",
    "adsystem": "système de pub", "doubleclick": "régie Google", "googleads": "régie Google", "adtech": "technologie publicitaire",
    "tracking": "suivi publicitaire", "tracker": "traceur", "trackers": "traceur", "telemetry": "télémétrie", "beacon": "balise de suivi",
    "pixel": "pixel de suivi", "analytics": "mesure d'audience", "metrics": "compteur de lecture", "stats": "compteur de lecture",
    "advert": "publicité", "adverts": "publicité", "advertising": "publicité", "sponsor": "parrainage", "prebid": "enchères publicitaires",
}


def ressemble_a_pub(domaine: str) -> Optional[str]:
    """Le motif lisible si un libellé du nom évoque une pub ou un traceur, sinon None."""
    for libelle in str(domaine).lower().split("."):
        for mot in re.split(r"[-_0-9]+", libelle):
            if mot in MOTS_PUB:
                return MOTS_PUB[mot]
    return None


def suspects(evenements: Iterable[dict], noms_par_ip: Dict[str, str], ignores: Set[str], deja_bloques: Set[str]) -> List[dict]:
    """Noms NON bloqués qui ressemblent à une pub, par appareil. `evenements` : lignes du magasin (client, domaine, decision)."""
    par: Dict[tuple, dict] = {}
    for e in evenements:
        d, nom = e["domaine"], noms_par_ip.get(e["client"])
        if nom is None or e["decision"] == "BLOCKED" or d in ignores or d in deja_bloques:
            continue
        motif = ressemble_a_pub(d)
        if not motif:
            continue
        x = par.setdefault((nom, d), {"appareil": nom, "domaine": d, "requetes": 0, "motif": motif})
        x["requetes"] += 1
    return sorted(par.values(), key=lambda x: (-x["requetes"], x["domaine"]))[:SUSPECTS_MAX]


def appareils(etat: dict, blocages: Dict[str, int], derniere_vue: Dict[str, int]) -> List[dict]:
    """Une carte par nom d'appareil. `blocages` : blocages du jour par adresse. Protégé = toutes ses adresses en mode auto."""
    par: Dict[str, List[dict]] = {}
    for c in etat["clients"]:
        par.setdefault(c["nom"], []).append(c)
    cartes = []
    for nom, cs in par.items():
        protege = all(c["mode"] == "auto" for c in cs)
        cartes.append({"nom": nom, "adresses": len(cs), "protege": protege,
                       "modes": sorted({c["mode"] for c in cs}),
                       "origine": cs[0].get("origine", "admin"),
                       "blocages_jour": sum(blocages.get(c["ip"], 0) for c in cs),
                       "derniere_vue": max([derniere_vue.get(c["ip"], 0) for c in cs] or [0])})
    return sorted(cartes, key=lambda c: (not c["protege"], c["nom"].lower()))


def verifier_application(etat: dict, nom: str, dropin: str) -> Optional[str]:
    """None si le drop-in reflète l'état de l'appareil `nom`, sinon une phrase qui dit ce qui diverge."""
    if not etat.get("actif", True):
        return None
    lignes = {}
    for l in dropin.splitlines():
        m = re.match(r"\s*access-control-view:\s+(\S+?)/(?:32|128)\s+(\S+)\s*$", l)
        if m:
            lignes[m.group(1)] = m.group(2)
    for c in (x for x in etat["clients"] if x["nom"] == nom):
        attendu = None if c["mode"] == "off" else (f"sbx-tv-auto-{dnstv._slug(c['nom'])}" if c["mode"] == "auto" else f"sbx-tv-{c['mode']}")
        if lignes.get(c["ip"]) != attendu:
            return f"l'adresse {c['ip']} n'est pas au bon état dans le filtre"
    return None
