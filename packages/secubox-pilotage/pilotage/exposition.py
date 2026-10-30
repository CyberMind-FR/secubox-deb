# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: plan d'exposition des box du maillage (#3126, L5 tâche 6, exigence E4)

`secubox-relais-maillage` (root, sur le maître) relaie les noms `<svc>.<box>.secubox.in` des pairs. Une box légère n'a pas de
webos : ses noms et ports viennent de l'inventaire de son agent (`Device.X_SECUBOX_Exposure.Names|Ports`). Le service écrit à
chaque tour d'inventaire, à un chemin FIXE de son dossier (`/var/lib/secubox/pilotage/exposition.json`, 0640), un plan que le
script root relit sans suivre de lien et revalide en entier : AUCUNE route HTTP sans jeton n'est ajoutée au contrôleur (même
patron que `vhosts.json` et le ctl `secubox-pilotage-vhost`).

Clé d'une entrée : l'ADRESSE maillée de la box (identité authentifiée par WireGuard, `identite.box_par_adresse`), avec son nom.
Les valeurs sont des déclarations d'un agent distant : seuls `<svc>.<box>.secubox.in` (svc `^[a-z0-9-]{1,40}$`, sans tiret en
tête ni en fin) et les ports entiers 1..65535 passent, listes bornées ; une box au nom ambigu, à la valeur tronquée ou hors du
réseau du maillage n'y figure pas (le relais garde alors son ancien chemin).
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterable

from pilotage import vhosts as V

NOMS = "Device.X_SECUBOX_Exposure.Names"
PORTS = "Device.X_SECUBOX_Exposure.Ports"
INTERFACE = V.INTERFACE
RE_SVC = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?")
RESEAU_MAILLAGE = ipaddress.ip_network("10.10.0.0/24")
NOMS_MAX = 64
PORTS_MAX = 256
BOXES_MAX = V.BOXES_MAX * 4


def _noms(box: str, valeur) -> list:
    if not isinstance(valeur, list):
        return []
    suffixe = f".{box}.{V.ZONE}"
    res = []
    for n in valeur:
        if isinstance(n, str) and n.endswith(suffixe) and RE_SVC.fullmatch(n[:-len(suffixe)]) and n not in res:
            res.append(n)
        if len(res) >= NOMS_MAX:
            break
    return sorted(res)


def _ports(valeur) -> list:
    if not isinstance(valeur, list):
        return []
    res = sorted({p for p in valeur if type(p) is int and 1 <= p <= 65535})
    return res[:PORTS_MAX]


def _adresse(a) -> str | None:
    try:
        ip = ipaddress.ip_address(a)
    except (TypeError, ValueError):
        return None
    return str(ip) if ip in RESEAU_MAILLAGE else None


def plan(lignes: Iterable[dict]) -> dict:
    """`lignes` : [{nom, adresse, reseau, inventaire: {valeurs, releve_le, tronques}}]. Un nom ou une adresse portés deux
    fois : aucune des box concernées (on ne choisit pas)."""
    cand = []
    for b in lignes:
        nom, adr = b.get("nom"), _adresse(b.get("adresse"))
        inv = b.get("inventaire") or {}
        val = inv.get("valeurs") or {}
        if b.get("reseau") != "maillage" or adr is None or not isinstance(nom, str) or not V.RE_BOX.fullmatch(nom):
            continue
        if NOMS not in val or not isinstance(val[NOMS], list) or set(inv.get("tronques") or ()) & {NOMS, PORTS}:
            continue
        cand.append({"adresse": adr, "box": nom, "distante": val.get(INTERFACE) == "distante",
                     "noms": _noms(nom, val[NOMS]), "ports": _ports(val.get(PORTS)),
                     "releve_le": float(inv["releve_le"]) if isinstance(inv.get("releve_le"), (int, float)) else 0.0})
    compte_n, compte_a = {}, {}
    for c in cand:
        compte_n[c["box"]] = compte_n.get(c["box"], 0) + 1
        compte_a[c["adresse"]] = compte_a.get(c["adresse"], 0) + 1
    sortie = [c for c in cand if compte_n[c["box"]] == 1 and compte_a[c["adresse"]] == 1]
    sortie.sort(key=lambda c: c["box"])
    return {"version": 1, "boxes": sortie[:BOXES_MAX]}


def ecrire_plan(chemin: Path, contenu: dict) -> bool:
    """Même écriture que le plan des vhosts (atomique, 0640, seulement s'il change)."""
    return V.ecrire_plan(chemin, contenu)
