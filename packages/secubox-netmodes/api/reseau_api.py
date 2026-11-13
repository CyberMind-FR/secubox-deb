# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Routes de lecture du réseau (#3190) : GET /reseau/{ports,clients,carte,materiel}. Lecture seule, aucune action sur une
interface.

Routes `def` (pool de threads) : lire_systeme() appelle subprocess, seul endroit du module à le faire.

#3688 : le matériel réel (materiel.lire, sysfs) décide d'abord. Sur une carte sans switch DSA, sans WAN dédié et sans br-lan
(un Raspberry Pi : eth0 et wlan0), les lectures du WAN eth2 et de br-lan ne sont pas lancées : elles sont « sans objet »
(`sans_objet`), jamais comptées « en panne ». Sur une carte routeur (MOCHAbin, ESPRESSObin), rien ne change."""
from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import re

from fastapi import APIRouter, Depends

from secubox_core.auth import est_admin_reel, require_jwt, require_lecture

from . import materiel
from . import reseau_lecture as lect

router = APIRouter(prefix="/reseau")

DELAI = 5            # secondes par commande
TTL_CACHE = 5.0
SYS_NET = Path("/sys/class/net")
BAUX = Path("/var/lib/misc/dnsmasq.leases")
RESEAU_D = Path("/etc/systemd/network")
SYS_MATERIEL = SYS_NET                          # sysfs lu pour le matériel (#3688) ; une arborescence simulée en test
MODELES = (Path("/proc/device-tree/model"), Path("/sys/firmware/devicetree/base/model"))

SOURCES = {          # clé -> argv (lecture seule : ip/bridge en mode show)
    "ip_link": ["ip", "-j", "link"],
    "fdb": ["bridge", "-j", "fdb", "show", "br", lect.PONT_LAN],
    "voisins_lan": ["ip", "-j", "neigh", "show", "dev", lect.PONT_LAN],
    "wan_addr": ["ip", "-j", "-4", "addr", "show", "dev", lect.WAN],
    "route_defaut": ["ip", "-j", "-4", "route", "show", "default"],
    "voisins_wan": ["ip", "-j", "neigh", "show", "dev", lect.WAN],
    "membres_lxc": ["ip", "-j", "link", "show", "master", lect.PONT_LXC],
    "liens_wg": ["ip", "-j", "link", "show", "type", "wireguard"],
    "adresses": ["ip", "-j", "addr", "show"],          # adresses des interfaces physiques (#3688)
}
# Lectures du matériel routeur (WAN eth2, pont br-lan, baux du DHCP du LAN) : sans objet sur une carte qui n'en a pas (#3688).
SOURCES_ROUTEUR = ("fdb", "voisins_lan", "wan_addr", "voisins_wan", "baux")

_cache: dict[str, Any] = {}
_verrou = threading.Lock()                      # une lecture du système à la fois
# Génération du cache, avancée par invalider() : une lecture commencée avant n'inscrit pas son résultat (#3190, I3).
_generation = 0
_verrou_generation = threading.Lock()           # bref : jamais tenu pendant une lecture


def _json(argv: list[str]):
    r = subprocess.run(argv, timeout=DELAI, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise OSError(f"{argv[0]} rc {r.returncode}")
    return json.loads(r.stdout or "[]")


def _sys(port: str, fichier: str) -> str | None:
    try:
        return (SYS_NET / port / fichier).read_text().strip()
    except OSError:
        return None


COUPE_RE = re.compile(r"^04-secubox-port-(lan[0-3])-coupe\.network$")


def ports_coupes(noms: list[str]) -> set[str]:
    """Ports coupés d'après les noms de fichiers (contrat avec la tâche 2) ; tout autre nom est ignoré."""
    return {m.group(1) for n in noms if (m := COUPE_RE.fullmatch(n))}


ISOLE_RE = re.compile(r"^04-secubox-port-(lan[0-3])-isole\.network$")


def ports_isoles(noms: list[str]) -> set[str]:
    """Ports isolés (#3201) d'après les noms de fichiers, même listage que les coupures ; tout autre nom est ignoré."""
    return {m.group(1) for n in noms if (m := ISOLE_RE.fullmatch(n))}


def invalider() -> None:
    """Après une action sur un port : le prochain relevé est relu. Une lecture en vol, commencée avant, rend son
    résultat à son appelant mais ne l'inscrit pas au cache (il montrerait l'état d'avant l'action) ; on ne l'attend pas."""
    global _generation
    with _verrou_generation:
        _generation += 1
        _cache.clear()


def lire_systeme() -> dict:
    """Toutes les lectures, cache mémoire de 5 s. Source en échec : clé None et nom dans `pannes`."""
    with _verrou:
        with _verrou_generation:
            if _cache.get("t") and time.monotonic() - _cache["t"] < TTL_CACHE:
                return _cache["valeur"]
            generation = _generation
        res: dict[str, Any] = {}
        pannes: list[str] = []
        mat = materiel.lire(SYS_MATERIEL, MODELES)
        # Seul un « non » lu dans sysfs retire les lectures du routeur ; sysfs illisible (None) : tout est lu, comme avant.
        sans_objet = list(SOURCES_ROUTEUR) if mat["vue_routeur"] is False else []
        for cle, argv in SOURCES.items():
            if cle in sans_objet:
                res[cle] = None
                continue
            try:
                res[cle] = _json(argv)
            except (OSError, ValueError, subprocess.SubprocessError):
                res[cle] = None
                pannes.append(cle)
        res["sysfs"] = {p: {f: _sys(p, f) for f in ("carrier", "speed", "operstate")} for p in lect.ROLES}
        try:
            res["baux"] = None if "baux" in sans_objet else BAUX.read_text()
        except OSError:
            res["baux"] = None
            pannes.append("baux")
        try:
            noms = [f.name for f in RESEAU_D.iterdir()]
            res["coupes"], res["isoles"] = ports_coupes(noms), ports_isoles(noms)
        except OSError:                         # un seul listage : s'il échoue, coupés et isolés sont tous deux inconnus
            res["coupes"] = res["isoles"] = None
            pannes += ["coupes", "isoles"]
        res["pannes"] = pannes
        res["sans_objet"] = sans_objet
        res["materiel"] = materiel.completer(mat, res["adresses"], res["route_defaut"])
        with _verrou_generation:
            if generation == _generation:          # aucune invalidation pendant la lecture : elle est à jour
                _cache.update(t=time.monotonic(), valeur=res)
        return res


def _macs_box(s: dict) -> set[str]:
    return {str(l["address"]).lower() for l in s.get("ip_link") or [] if isinstance(l, dict) and l.get("address")}


def _restreint(user: Any) -> bool:
    """Tout lecteur qui n'est pas un ADMINISTRATEUR RÉEL (`est_admin_reel` du socle, #1581) : anonyme du tableau de
    bord, usager, appareil enrôlé, invité. Il reçoit des comptes, jamais les MAC apprises ni les voisins du WAN."""
    return not (isinstance(user, dict) and est_admin_reel(user))


def _pannes(s: dict, cles: tuple[str, ...]) -> list[str]:
    return [p for p in s["pannes"] if p in cles]


def _sans_objet(s: dict, cles: tuple[str, ...]) -> list[str]:
    return [p for p in s.get("sans_objet") or [] if p in cles]


@router.get("/ports")
def lire_ports(user: Any = Depends(require_lecture)) -> dict:
    s = lire_systeme()
    if s["ip_link"] is None:
        liste = None
    else:
        liste = lect.ports(s["ip_link"], s["fdb"], s["sysfs"], s["coupes"], _macs_box(s), s["isoles"])
        if _restreint(user):                    # pas un administrateur réel : ni MAC apprises, des comptes seulement
            for p in liste:
                p["nb_appareils"] = None if p["macs"] is None else len(p["macs"])
                del p["macs"]
    return {"ports": liste, "pannes": _pannes(s, ("ip_link", "fdb", "coupes", "isoles")),
            "sans_objet": _sans_objet(s, ("ip_link", "fdb", "coupes", "isoles"))}


@router.get("/clients")
def lire_clients(_user: Any = Depends(require_jwt)) -> dict:
    s = lire_systeme()
    return {"clients": lect.clients(s["baux"], s["fdb"], s["voisins_lan"]),
            "pannes": _pannes(s, ("baux", "voisins_lan", "fdb")), "sans_objet": _sans_objet(s, ("baux", "voisins_lan", "fdb"))}


@router.get("/carte")
def lire_carte(user: Any = Depends(require_lecture)) -> dict:
    s = lire_systeme()
    c = lect.carte(s["wan_addr"], s["route_defaut"], s["voisins_wan"], s["membres_lxc"], s["liens_wg"])
    if _restreint(user) and c["wan"] and c["wan"]["voisins"] is not None:
        c["wan"]["nb_voisins"] = len(c["wan"]["voisins"])
        del c["wan"]["voisins"]
    cles = ("wan_addr", "route_defaut", "voisins_wan", "membres_lxc", "liens_wg")
    return {"carte": c, "pannes": _pannes(s, cles), "sans_objet": _sans_objet(s, cles), "materiel": s.get("materiel")}


@router.get("/materiel")
def lire_materiel(_user: Any = Depends(require_lecture)) -> dict:
    """Matériel réel (#3688) : l'hôte du panneau Réseau choisit ses onglets ; None si la lecture n'a pas eu lieu."""
    return {"materiel": lire_systeme().get("materiel")}
