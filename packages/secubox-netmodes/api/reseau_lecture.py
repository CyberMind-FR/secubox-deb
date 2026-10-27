# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lecture du réseau (#3190) : fonctions pures sur des sorties déjà lues (`ip -j`, `bridge -j`, baux dnsmasq).

Aucun appel système ici : reseau_api.lire_systeme() lit, ce module interprète. Lecture seule, jamais d'action."""
from __future__ import annotations

from . import isolement

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


def ports(ip_link: list, fdb: list | None, sysfs: dict, coupes: set | None, macs_box: set,
          isoles: set | None) -> list[dict]:
    """fdb, coupes ou isoles None (source en échec) : `macs`/`plusieurs_appareils`, `coupe` ou `isole` valent None, jamais
    « aucun ». Seuls les ports lan* s'isolent (#3201) : `reseau_isole` est le réseau du port isolé, sinon None."""
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
        macs = None if fdb is None else par_port.get(nom, [])
        sortie.append({
            "nom": nom, "role": role,
            "porteuse": None if carrier is None else carrier == 1,
            "vitesse_mbps": vitesse if vitesse is not None and vitesse > 0 else None,
            "etat_admin": "up" if "UP" in (lien.get("flags") or []) else "down",
            "maitre": lien.get("master"),
            "macs": macs, "plusieurs_appareils": None if macs is None else len(macs) > 1,
            "coupe": None if coupes is None else nom in coupes,
            "isole": None if isoles is None else role == "lan" and nom in isoles,
            "reseau_isole": str(isolement.passerelle(nom).network) if role == "lan" and isoles and nom in isoles else None,
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


def clients(baux: str | None, fdb: list | None, voisins: list | None) -> list[dict] | None:
    """baux None : clients bâtis des voisins seuls, chacun marqué `bail_inconnu`. baux et voisins None : None."""
    if baux is None and voisins is None:
        return None
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
        c = {"mac": mac, "ip": v["dst"], "nom": "", "port": port_de.get(mac), "source": "voisin", "expire": None}
        if baux is None:
            c["bail_inconnu"] = True
        sortie.append(c)
    return sortie


def carte(wan_addr, route_defaut, voisins_wan, membres_lxc, liens_wg) -> dict:
    """Chaque bloc vaut None quand sa source a échoué (wan : adresse ; voisins : None si ip neigh a échoué)."""
    wan = None
    if wan_addr is not None:
        adresse = None
        for lien in wan_addr:
            for a in lien.get("addr_info") or []:
                if a.get("family", "inet") == "inet" and a.get("local"):
                    adresse = f"{a['local']}/{a.get('prefixlen')}"
                    break
        passerelle = None if route_defaut is None else next(
            (r.get("gateway") for r in route_defaut if r.get("gateway")), None)
        wan = {"interface": WAN, "adresse": adresse, "passerelle": passerelle,
               "voisins": None if voisins_wan is None else
               [{"ip": v["dst"], "mac": v["lladdr"]} for v in voisins_wan if v.get("dst") and v.get("lladdr")]}
    return {
        "wan": wan,
        "lxc": None if membres_lxc is None else {"pont": PONT_LXC, "actifs": len(membres_lxc)},
        "tunnels": None if liens_wg is None else
        [{"nom": l.get("ifname"), "etat": "up" if "UP" in (l.get("flags") or []) else "down"} for l in liens_wg],
    }
