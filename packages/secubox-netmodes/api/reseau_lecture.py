# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lecture du réseau (#3190) : fonctions pures sur des sorties déjà lues (`ip -j`, `bridge -j`, baux dnsmasq).

Aucun appel système ici : reseau_api.lire_systeme() lit, ce module interprète. Lecture seule, jamais d'action."""
from __future__ import annotations

ROLES = {"eth2": "wan", "eth1": "conduit", "eth0": "sfp", "lan0": "lan", "lan1": "lan", "lan2": "lan", "lan3": "lan"}
PONT_LAN = "br-lan"
PONT_LXC = "br-lxc"
WAN = "eth2"


def _entier(v) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _fdb_apprises(fdb) -> list[dict]:
    """Entrées apprises : ni permanentes ni `self`."""
    sortie = []
    for e in fdb or []:
        if not isinstance(e, dict) or not e.get("mac") or not e.get("ifname"):
            continue
        if e.get("state") == "permanent" or "permanent" in (e.get("flags") or []) or "self" in (e.get("flags") or []):
            continue
        sortie.append(e)
    return sortie


def ports(ip_link: list, fdb: list, sysfs: dict, coupes: set, macs_box: set) -> list[dict]:
    macs_box = {m.lower() for m in macs_box}
    par_port: dict[str, list[str]] = {}
    for e in _fdb_apprises(fdb):
        mac = str(e["mac"]).lower()
        if mac in macs_box:
            continue
        liste = par_port.setdefault(e["ifname"], [])
        if mac not in liste:
            liste.append(mac)
    liens = {l.get("ifname"): l for l in ip_link or [] if isinstance(l, dict)}
    sortie = []
    for nom, role in ROLES.items():
        lien = liens.get(nom)
        if lien is None:
            continue
        sys_p = (sysfs or {}).get(nom) or {}
        carrier = _entier(sys_p.get("carrier"))
        vitesse = _entier(sys_p.get("speed"))
        macs = par_port.get(nom, [])
        sortie.append({
            "nom": nom, "role": role,
            "porteuse": None if carrier is None else carrier == 1,
            "vitesse_mbps": vitesse if vitesse is not None and vitesse > 0 else None,
            "etat_admin": "up" if "UP" in (lien.get("flags") or []) else "down",
            "maitre": lien.get("master"),
            "macs": macs, "plusieurs_appareils": len(macs) > 1,
            "coupe": nom in coupes,
        })
    return sortie


def _baux(texte: str) -> list[dict]:
    sortie = []
    for ligne in (texte or "").splitlines():
        t = ligne.split()
        if len(t) < 4 or ":" not in t[1]:
            continue
        sortie.append({"mac": t[1].lower(), "ip": t[2], "nom": "" if t[3] == "*" else t[3], "expire": _entier(t[0])})
    return sortie


def clients(baux: str, fdb: list, voisins: list) -> list[dict]:
    port_de = {}
    for e in _fdb_apprises(fdb):
        port_de.setdefault(str(e["mac"]).lower(), e["ifname"])
    sortie, vus = [], set()
    for b in _baux(baux):
        if b["mac"] in vus:
            continue
        vus.add(b["mac"])
        sortie.append({"mac": b["mac"], "ip": b["ip"], "nom": b["nom"], "port": port_de.get(b["mac"]),
                       "source": "bail", "expire": b["expire"]})
    for v in voisins or []:
        mac = str(v.get("lladdr") or "").lower()
        if not mac or not v.get("dst") or mac in vus or "FAILED" in (v.get("state") or []):
            continue
        vus.add(mac)
        sortie.append({"mac": mac, "ip": v["dst"], "nom": "", "port": port_de.get(mac),
                       "source": "voisin", "expire": None})
    return sortie


def carte(wan_addr: list, route_defaut: list, voisins_wan: list, membres_lxc: list, liens_wg: list) -> dict:
    adresse = None
    for lien in wan_addr or []:
        for a in lien.get("addr_info") or []:
            if a.get("family", "inet") == "inet" and a.get("local"):
                adresse = f"{a['local']}/{a.get('prefixlen')}"
                break
    passerelle = next((r.get("gateway") for r in route_defaut or [] if r.get("gateway")), None)
    return {
        "wan": {"interface": WAN, "adresse": adresse, "passerelle": passerelle,
                "voisins": [{"ip": v["dst"], "mac": v["lladdr"]} for v in voisins_wan or []
                            if v.get("dst") and v.get("lladdr")]},
        "lxc": {"pont": PONT_LXC, "actifs": len(membres_lxc or [])},
        "tunnels": [{"nom": l.get("ifname"), "etat": "up" if "UP" in (l.get("flags") or []) else "down"}
                    for l in liens_wg or []],
    }
