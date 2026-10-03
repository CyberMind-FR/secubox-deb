# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: fiche « DNS de la box » (#1938) — quelle adresse donner aux appareils, et Unbound l'écoute-t-il ?

Analyse de TEXTE seulement (sorties de `ip -6/-4 -o addr`, `ip route show default`, `ss -H -lnu`) : aucune commande ici, aucun privilège, rien n'est modifié.
Elle montre ce que la box OFFRE ; elle ne peut pas lire les réglages de la Freebox, donc ne sait pas si l'adresse y a été saisie.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Set

RE_ADDR = re.compile(r"^\d+:\s+(?P<dev>\S+)\s+inet6?\s+(?P<addr>\S+)/\d+\s+(?P<reste>.*)$")
RE_VALID = re.compile(r"valid_lft\s+(?P<v>forever|\d+)")
RE_DEFAUT_DEV = re.compile(r"^default\s+.*\bdev\s+(?P<dev>\S+)")


def _adresse(brut: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(brut.split("%")[0]))
    except ValueError:
        return None


def interface_du_lan(route_defaut: str) -> Optional[str]:
    for ligne in route_defaut.splitlines():
        m = RE_DEFAUT_DEV.match(ligne.strip())
        if m:
            return m["dev"]
    return None


def ecoutes_dns(ss: str) -> Set[str]:
    """Adresses (normalisées) sur lesquelles un socket UDP écoute le port 53."""
    out: Set[str] = set()
    for ligne in ss.splitlines():
        champs = ligne.split()
        if len(champs) < 5:
            continue
        local = champs[3]
        hote, _, port = local.rpartition(":")
        if port != "53":
            continue
        a = _adresse(hote.strip("[]"))
        if a:
            out.add(a)
    return out


def _type(famille: int, reste: str) -> str:
    if famille == 4:
        return "ipv4"
    if "temporary" in reste:
        return "temporaire"
    valide = RE_VALID.search(reste)
    if "dynamic" in reste or (valide and valide["v"] != "forever"):
        return "slaac"
    return "stable"


def dns_box(ip6: str, ip4: str, route_defaut: str, ss: str) -> Dict:
    dev = interface_du_lan(route_defaut)
    ecoute = ecoutes_dns(ss)
    adresses: List[dict] = []
    if dev:
        for famille, sortie in ((4, ip4), (6, ip6)):
            for ligne in sortie.splitlines():
                m = RE_ADDR.match(ligne.strip())
                if not m or m["dev"] != dev:
                    continue
                a = _adresse(m["addr"])
                if a is None:
                    continue
                adresses.append({"adresse": a, "famille": famille, "type": _type(famille, m["reste"]), "ecoute": a in ecoute})
    alertes: List[str] = []
    if not dev:
        alertes.append("Interface du LAN introuvable (pas de route par défaut) : rien à afficher.")
    else:
        stables = [a for a in adresses if a["famille"] == 6 and a["type"] == "stable"]
        if not stables:
            alertes.append("Aucune IPv6 stable sur le LAN : une adresse SLAAC expire avec le préfixe. Posez une adresse statique avant de la saisir dans la Freebox.")
        for a in adresses:
            if not a["ecoute"] and a["type"] in ("stable", "ipv4"):
                alertes.append(f"{a['adresse']} est sur l'interface mais Unbound n'écoute pas dessus : les appareils n'obtiendraient aucune réponse.")
    return {"interface": dev, "adresses": adresses, "alertes": alertes}
