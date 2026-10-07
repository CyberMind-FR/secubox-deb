# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: freebox :: normalisation des réponses Freebox OS
CyberMind — https://cybermind.fr

Fonctions PURES : réponses de la Freebox → données stables et lisibles pour le panneau et les autres modules. Tolérantes aux champs
absents (l'API évolue selon les versions de la Freebox). Jamais d'adresse MAC complète : un identifiant stable et les trois derniers octets.
"""
import hashlib
import ipaddress

# Ports dont l'ouverture vers Internet mérite l'attention : accès à distance, partage de fichiers, bases de données.
PORTS_SENSIBLES = {21, 22, 23, 25, 110, 135, 137, 138, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}


def est_sensible(debut, fin):
    try:
        debut, fin = int(debut), int(fin)
    except (TypeError, ValueError):
        return False
    return any(debut <= p <= fin for p in PORTS_SENSIBLES)


def _mac(h):
    m = ((h.get("l2ident") or {}).get("id") or "").lower()
    return m if len(m.split(":")) == 6 else ""


def _type_ipv6(adresse):
    try:
        a = ipaddress.ip_address(adresse)
    except ValueError:
        return "autre"
    if a.version != 6:
        return "autre"
    if a in ipaddress.ip_network("2000::/3"):
        return "publique"
    return "autre"


def appareils(hotes):
    sortie = []
    for h in hotes or []:
        mac = _mac(h)
        if not mac:
            continue
        noms = [x.get("name") for x in (h.get("names") or []) if x.get("name")]
        nom = (h.get("primary_name") or "").strip() or (noms[0] if noms else "") or "Appareil " + mac[-8:]
        l3 = h.get("l3connectivities") or []
        sortie.append({
            "id": hashlib.sha256(mac.encode()).hexdigest()[:10], "mac_fin": mac[-8:], "nom": nom, "type": h.get("host_type") or "",
            "fabricant": h.get("vendor_name") or "", "actif": bool(h.get("active")), "joignable": bool(h.get("reachable")),
            "ipv4": [x["addr"] for x in l3 if x.get("af") == "ipv4" and x.get("addr")],
            "ipv6_publiques": [x["addr"] for x in l3 if x.get("af") == "ipv6" and x.get("addr") and _type_ipv6(x["addr"]) == "publique"],
            "vu_derniere_fois": h.get("last_activity") or None,
        })
    return sorted(sortie, key=lambda a: (not a["actif"], a["nom"].lower()))


def connexion(conn, cfg6):
    conn, cfg6 = conn or {}, cfg6 or {}

    def mbit(v):
        return int(v) // 1_000_000 if isinstance(v, (int, float)) else None
    return {
        "en_ligne": conn.get("state") == "up", "media": conn.get("media") or conn.get("type") or "",
        "ipv4_publique": conn.get("ipv4") or "", "ipv6": conn.get("ipv6") or "",
        "debit_max_descendant_mbit": mbit(conn.get("bandwidth_down")), "debit_max_montant_mbit": mbit(conn.get("bandwidth_up")),
        "ipv6_actif": cfg6.get("ipv6_enabled") if "ipv6_enabled" in cfg6 else None,
        "pare_feu_ipv6": cfg6.get("ipv6_firewall") if "ipv6_firewall" in cfg6 else None,
        "prefixes_ipv6": [d["prefix"] for d in (cfg6.get("delegations") or []) if d.get("prefix")],
    }


def _source(src):
    return "tout Internet" if src in (None, "", "0.0.0.0", "::") else src


def redirections(liste):
    sortie = []
    for r in liste or []:
        debut, fin = r.get("wan_port_start"), r.get("wan_port_end") or r.get("wan_port_start")
        sortie.append({
            "id": r.get("id"), "actif": bool(r.get("enabled")), "protocole": r.get("ip_proto") or "tcp",
            "port_externe_debut": debut, "port_externe_fin": fin, "appareil_ip": r.get("lan_ip") or "", "port_local": r.get("lan_port"),
            "source": _source(r.get("src_ip")), "commentaire": r.get("comment") or "", "nom_appareil": r.get("hostname") or "",
            "sensible": est_sensible(debut, fin) or est_sensible(r.get("lan_port"), r.get("lan_port")),
        })
    return sortie


def exceptions_ipv6(liste):
    sortie = []
    for r in liste or []:
        debut = r.get("port_start") or r.get("wan_port_start")
        fin = r.get("port_end") or r.get("wan_port_end") or debut
        sortie.append({"id": r.get("id"), "actif": bool(r.get("enabled")), "protocole": r.get("ip_proto") or "tcp",
                       "appareil": r.get("ip") or r.get("lan_ip") or "", "port_debut": debut, "port_fin": fin,
                       "commentaire": r.get("comment") or "", "sensible": est_sensible(debut, fin)})
    return sortie
