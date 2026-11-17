# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: fiche « DNS de la box » (#1938) — quelle adresse donner aux appareils, et Unbound l'écoute-t-il ?

Analyse de TEXTE seulement (sorties de `ip -6/-4 -o addr`, `ip route show default`, `ss -H -lnu`) : aucune commande ici, aucun privilège, rien n'est modifié.
Elle montre ce que la box OFFRE ; ce que la Freebox annonce se lit dans l'onglet « DNS du réseau » de la page Freebox (#3769).
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


def derivee_de_la_mac(adresse: str) -> bool:
    """IPv6 SLAAC dont l'identifiant est tiré de la MAC (EUI-64, `…ff:fe…`) : elle ne change pas tant que le préfixe ne change
    pas, exactement comme une adresse statique ; utilisable comme DNS (#3769, gk7 du 17/11)."""
    try:
        b = ipaddress.IPv6Address(adresse).packed
    except ValueError:
        return False
    return b[11] == 0xFF and b[12] == 0xFE


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
                t = _type(famille, m["reste"])
                if t == "slaac" and derivee_de_la_mac(a):
                    t = "slaac_mac"
                adresses.append({"adresse": a, "famille": famille, "type": t, "ecoute": a in ecoute})
    alertes: List[str] = []
    if not dev:
        alertes.append("Interface du LAN introuvable (pas de route par défaut) : rien à afficher.")
    else:
        stables = [a for a in adresses if a["famille"] == 6 and a["type"] in ("stable", "slaac_mac")]
        if not stables:
            alertes.append("Aucune IPv6 durable sur le LAN (ni statique, ni dérivée de la MAC) : les appareils en IPv6 n'auraient pas de DNS fiable.")
        for a in adresses:
            if not a["ecoute"] and a["type"] in ("stable", "slaac_mac", "ipv4"):
                alertes.append(f"{a['adresse']} est sur l'interface mais Unbound n'écoute pas dessus : les appareils n'obtiendraient aucune réponse.")
    return {"interface": dev, "adresses": adresses, "alertes": alertes}
