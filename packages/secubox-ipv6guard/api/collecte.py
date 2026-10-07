# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: ipv6guard :: collecte PASSIVE
CyberMind — https://cybermind.fr

On n'envoie RIEN aux appareils : on lit ce que la box voit déjà — la table des voisins (`ip -6 neigh`, `ip -4 neigh`) et les
annonces mDNS (`avahi-browse`) — et on en fait des appareils lisibles : un appareil = une adresse MAC, avec ses adresses
publiques (joignables depuis Internet si le pare-feu de la Freebox les laisse), ses services annoncés et un nom clair.

Fonctions PURES (texte → données) : le module les teste sur des échantillons réels, sans réseau.
"""
import ipaddress
import re

_ETATS_VALIDES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
_ORDRE_ETAT = {"REACHABLE": 0, "PERMANENT": 0, "DELAY": 1, "PROBE": 1, "STALE": 2, "NOARP": 3}
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def type_adresse(adresse):
    """publique (2000::/3, joignable depuis Internet si le pare-feu l'autorise) | privee (fc00::/7) | locale (fe80::/10) | autre."""
    try:
        a = ipaddress.ip_address(adresse)
    except ValueError:
        return "autre"
    if a.version != 6:
        return "autre"
    if a in ipaddress.ip_network("2000::/3"):
        return "publique"
    if a in ipaddress.ip_network("fc00::/7"):
        return "privee"
    if a in ipaddress.ip_network("fe80::/10"):
        return "locale"
    return "autre"


def parse_voisins(texte):
    """Lignes de `ip -N neigh show` → [{adresse, interface, mac, etat, routeur}] ; sans MAC (FAILED/INCOMPLETE) : écartées."""
    sortie = []
    for ligne in (texte or "").splitlines():
        m = re.match(r"^(\S+)\s+dev\s+(\S+)\s+(?:lladdr\s+(\S+)\s*)?(.*)$", ligne.strip())
        if not m:
            continue
        adresse, interface, mac, reste = m.groups()
        if not mac or not _MAC.match(mac.lower()):
            continue
        mots = reste.split()
        etat = next((w for w in reversed(mots) if w in _ETATS_VALIDES), "")
        if not etat:
            continue
        sortie.append({"adresse": adresse, "interface": interface, "mac": mac.lower(), "etat": etat, "routeur": "router" in mots})
    return sortie


def regrouper(voisins6, voisins4, interfaces_lan=None):
    """Un appareil par adresse MAC. `interfaces_lan` : si donné, seules ces interfaces comptent (les ponts de conteneurs, non)."""
    par_mac = {}
    for v in voisins6:
        if interfaces_lan is not None and v["interface"] not in interfaces_lan:
            continue
        a = par_mac.setdefault(v["mac"], {"mac": v["mac"], "interface": v["interface"], "adresses_publiques": [],
                                          "adresses_privees": [], "adresses_locales": [], "ipv4": [], "routeur": False,
                                          "etat": v["etat"]})
        t = type_adresse(v["adresse"])
        liste = {"publique": "adresses_publiques", "privee": "adresses_privees", "locale": "adresses_locales"}.get(t)
        if liste and v["adresse"] not in a[liste]:
            a[liste].append(v["adresse"])
        a["routeur"] = a["routeur"] or v["routeur"]
        if _ORDRE_ETAT.get(v["etat"], 9) < _ORDRE_ETAT.get(a["etat"], 9):
            a["etat"] = v["etat"]
    for v in voisins4:
        a = par_mac.get(v["mac"])
        if a and v["adresse"] not in a["ipv4"]:
            a["ipv4"].append(v["adresse"])
    return sorted(par_mac.values(), key=lambda a: (not a["adresses_publiques"], a["mac"]))


# ── mDNS ─────────────────────────────────────────────────────────────────────
_ANNONCES_TECHNIQUES = {"_device-info._tcp", "device info", "_workstation._tcp", "_sleep-proxy._udp", "_companion-link._tcp",
                        "_rdlink._tcp", "_apple-mobdev2._tcp", "_dns-sd._udp", "_services._dns-sd._udp"}

_SERVICES = {
    "_ipp._tcp": ("Imprimante", False), "_ipps._tcp": ("Imprimante", False), "_printer._tcp": ("Imprimante", False),
    "_pdl-datastream._tcp": ("Imprimante", False), "_scanner._tcp": ("Scanner", False),
    "_airplay._tcp": ("AirPlay (écran ou enceinte)", False), "_raop._tcp": ("AirPlay (audio)", False),
    "_googlecast._tcp": ("Chromecast / Google Cast", False), "_spotify-connect._tcp": ("Spotify Connect", False),
    "_hap._tcp": ("Maison connectée (HomeKit)", False), "_homekit._tcp": ("Maison connectée (HomeKit)", False),
    "_matter._tcp": ("Maison connectée (Matter)", False), "_http._tcp": ("Page web", False), "_https._tcp": ("Page web sécurisée", False),
    "_ssh._tcp": ("Accès à distance (SSH)", True), "_sftp-ssh._tcp": ("Transfert de fichiers (SFTP)", True),
    "_smb._tcp": ("Partage de fichiers (Windows)", True), "_afpovertcp._tcp": ("Partage de fichiers (Apple)", True),
    "_nfs._tcp": ("Partage de fichiers (NFS)", True), "_adisk._tcp": ("Disque réseau", True),
    "_rfb._tcp": ("Bureau à distance (VNC)", True), "_telnet._tcp": ("Accès à distance (Telnet)", True),
    "_ftp._tcp": ("Transfert de fichiers (FTP)", True), "_daap._tcp": ("Bibliothèque musicale", False),
    "_mqtt._tcp": ("Objets connectés (MQTT)", True), "_homeassistant._tcp": ("Maison connectée (Home Assistant)", False),
}


def est_service(type_):
    return (type_ or "").strip().lower() not in _ANNONCES_TECHNIQUES and bool(type_)


def libelle_service(type_):
    """Nom en langage courant d'un type mDNS, et si ce service mérite l'attention (accès, partage de fichiers…)."""
    t = (type_ or "").strip().lower()
    if t in _SERVICES:
        l, s = _SERVICES[t]
        return {"libelle": l, "sensible": s}
    brut = t.lstrip("_").split(".")[0] if t else "?"
    return {"libelle": f"Service « {brut} »", "sensible": False}


def _decode_nom(s):
    """avahi échappe les caractères en `\\NNN` décimal (espace = \\032)."""
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), s or "")


def parse_mdns(texte):
    """Sortie de `avahi-browse -a -r -t -p` : lignes `=;iface;proto;nom;type;domaine;hote;adresse;port;txt`."""
    sortie = []
    for ligne in (texte or "").splitlines():
        if not ligne.startswith("="):
            continue
        champs = ligne.split(";", 9)
        if len(champs) < 9:
            continue
        try:
            port = int(champs[8])
        except ValueError:
            continue
        sortie.append({"interface": champs[1], "proto": champs[2], "nom": _decode_nom(champs[3]), "type": champs[4],
                       "hote": champs[6], "adresse": champs[7], "port": port})
    return sortie


def _nom_court(hote):
    return re.sub(r"\.local\.?$", "", hote or "")


def rattacher(appareils, mdns):
    """Rattache noms et services aux appareils par ADRESSE (IPv6 ou IPv4 connue de l'appareil). Jamais l'adresse MAC en clair."""
    index = {}
    for a in appareils:
        for ad in a["adresses_publiques"] + a["adresses_privees"] + a["adresses_locales"] + a["ipv4"]:
            index[ad] = a
    resultat = []
    for a in appareils:
        resultat.append({**a, "services": [], "nom": "", "_noms": []})
    par_mac = {a["mac"]: a for a in resultat}
    for m in mdns:
        a = index.get(m["adresse"])
        if not a:
            continue
        cible = par_mac[a["mac"]]
        nom = _nom_court(m["hote"])
        if nom and nom not in cible["_noms"]:
            cible["_noms"].append(nom)
        if est_service(m["type"]):
            cle = (m["type"], m["port"])
            if not any((s["type"], s["port"]) == cle for s in cible["services"]):
                cible["services"].append({"type": m["type"], "port": m["port"], "nom": m["nom"], **libelle_service(m["type"])})
    for a in resultat:
        a["nom"] = (a["_noms"][0] if a["_noms"] else "Appareil " + a["mac"][-8:])
        del a["_noms"]
    return resultat
