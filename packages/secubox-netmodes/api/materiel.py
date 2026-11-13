# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Matériel réseau réel de la carte (#3688) : interfaces physiques, switch DSA, WAN dédié, lus dans sysfs.

La vue « routeur » du panneau Réseau (WAN, passerelle, switch, ports, clients du LAN, mode routeur) n'a de sens que sur une
carte qui porte un switch DSA ou un WAN distinct du LAN. AUCUN nom ni modèle de carte ne décide : seulement ce que le noyau
expose (`/sys/class/net/<if>/dsa` sur le conduit d'un switch, `DEVTYPE=dsa` sur ses ports, lien `device` d'une interface
physique, `wireless`/`DEVTYPE=wlan` du wifi, `type` 1 = Ethernet). Le modèle du device tree n'est lu que pour l'afficher.

Lecture seule de sysfs, aucun appel système ici : adresses et route par défaut sont jointes ensuite (`completer`) à partir
des sorties `ip -j` déjà lues par reseau_api. Une lecture impossible ne décide jamais « sans routeur » : `vue_routeur` vaut
alors None et la page garde la vue complète d'avant."""
from __future__ import annotations

import os
from pathlib import Path

PONT_LAN = "br-lan"                 # pont du mode routeur durable : présent, la vue routeur reste (#3189)
MODELE_MAX = 120


def _lire(p: Path) -> str | None:
    try:
        return p.read_text(errors="replace").strip()
    except (OSError, ValueError):   # attribut illisible (porteuse d'une interface descendue : EINVAL), absent
        return None


def _entier(v: str | None) -> int | None:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def _devtype(d: Path) -> str | None:
    for ligne in (_lire(d / "uevent") or "").splitlines():
        if ligne.startswith("DEVTYPE="):
            return ligne[len("DEVTYPE="):].strip() or None
    return None


def _genre(d: Path) -> str:
    devtype = _devtype(d)
    if (d / "dsa").is_dir():
        return "conduit_switch"     # l'interface Ethernet qui porte le switch DSA (attribut dsa/tagging)
    if devtype == "dsa":
        return "port_switch"        # un port du switch (lan0, wan…)
    if devtype == "wlan" or (d / "wireless").is_dir() or os.path.lexists(d / "phy80211"):
        return "wifi"
    if _lire(d / "type") == "1":
        return "filaire"            # ARPHRD_ETHER
    return "autre"


def _interface(d: Path) -> dict | None:
    """None pour une interface virtuelle (pont, tunnel, veth, boucle locale) : sans lien `device`."""
    if not os.path.lexists(d / "device"):
        return None
    carrier = _entier(_lire(d / "carrier"))
    vitesse = _entier(_lire(d / "speed"))
    return {
        "nom": d.name,
        "genre": _genre(d),
        "etat": (_lire(d / "operstate") or None),
        "porteuse": None if carrier is None else carrier == 1,
        "vitesse_mbps": vitesse if vitesse is not None and vitesse > 0 else None,
    }


def _modele(modeles: tuple[Path, ...]) -> str | None:
    for p in modeles:
        try:
            brut = p.read_bytes()
        except OSError:
            continue
        texte = brut.decode("utf-8", "replace").replace("\x00", " ").strip()
        return " ".join(texte.split())[:MODELE_MAX] or None
    return None


def lire(racine: Path, modeles: tuple[Path, ...] = ()) -> dict:
    """Interfaces physiques et décision de vue. `racine` : /sys/class/net (ou une arborescence simulée)."""
    modele = _modele(modeles)
    try:
        noms = sorted(p.name for p in racine.iterdir())
    except OSError:
        return {"modele": modele, "switch_dsa": None, "wan_dedie": None, "pont_lan": None, "vue_routeur": None,
                "interfaces": None, "pannes": ["sysfs"]}
    interfaces = [i for n in noms if (i := _interface(racine / n)) is not None]
    switch = any(i["genre"] in ("conduit_switch", "port_switch") for i in interfaces)
    filaires = [i for i in interfaces if i["genre"] == "filaire"]
    # WAN dédié : un port du switch étiqueté wan par le device tree, ou deux prises Ethernet hors switch (l'une sert de WAN,
    # l'autre de LAN). Une seule prise Ethernet, avec ou sans wifi, n'en a pas.
    wan_dedie = any(i["genre"] == "port_switch" and i["nom"].startswith("wan") for i in interfaces) or len(filaires) >= 2
    pont_lan = os.path.lexists(racine / PONT_LAN)
    return {"modele": modele, "switch_dsa": switch, "wan_dedie": wan_dedie, "pont_lan": pont_lan,
            "vue_routeur": switch or wan_dedie or pont_lan, "interfaces": interfaces, "pannes": []}


def completer(materiel: dict, adresses: list | None, route_defaut: list | None) -> dict:
    """Adresses globales (IPv4 et IPv6, jamais le lien local) et passerelle de la route par défaut, par interface.
    Source en échec : champ None pour chaque interface et nom de la source dans `pannes`, jamais une liste vide."""
    m = dict(materiel)
    pannes = list(m.get("pannes") or [])
    if adresses is None:
        pannes.append("adresses")
    if route_defaut is None:
        pannes.append("route_defaut")
    m["pannes"] = pannes
    if m.get("interfaces") is None:
        return m
    par_nom = {lien.get("ifname"): lien for lien in adresses or [] if isinstance(lien, dict)}
    passerelles: dict[str, str] = {}
    for r in route_defaut or []:
        if isinstance(r, dict) and r.get("dev") and r.get("gateway"):
            passerelles.setdefault(str(r["dev"]), str(r["gateway"]))
    sortie = []
    for i in m["interfaces"]:
        i = dict(i)
        if adresses is None:
            i["adresses"] = None
        else:
            i["adresses"] = [f"{a['local']}/{a.get('prefixlen')}" for a in (par_nom.get(i["nom"]) or {}).get("addr_info") or []
                             if isinstance(a, dict) and a.get("local") and a.get("scope", "global") == "global"]
        i["passerelle"] = None if route_defaut is None else passerelles.get(i["nom"])
        sortie.append(i)
    m["interfaces"] = sortie
    return m
