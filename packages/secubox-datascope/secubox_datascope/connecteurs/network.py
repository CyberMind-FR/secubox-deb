# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Connecteur network : appareils du NAC (SQLite, lecture seule) et débits des interfaces (netstats.json)."""
from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from ..store import Releve
from ._commun import empreinte, jour, suffixe_valide

SOURCE = "network"
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _inaccessible(motif: str) -> Releve:
    return Releve(source=SOURCE, etat="inaccessible", motif=motif, empreinte="")


def _lignes(nac_db: Path) -> List[sqlite3.Row]:
    db = sqlite3.connect(f"file:{nac_db}?mode=ro", uri=True, timeout=2)
    try:
        db.row_factory = sqlite3.Row
        return db.execute("SELECT mac, ip, hostname, interface, device_type, zone, last_seen, mac_random, "
                          "oui_vendor FROM devices").fetchall()
    finally:
        db.close()


def _ip(valeur: Any) -> str | None:
    try:
        a = ipaddress.ip_address(str(valeur).strip().split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.compressed


def _jour_sur(valeur: Any, repli: str) -> str:
    """Date d'un last_seen ; valeur corrompue (hors plage, négative, non numérique) : repli."""
    if isinstance(valeur, bool) or not isinstance(valeur, (int, float)) or valeur < 0:
        return repli
    try:
        return jour(valeur)
    except (OverflowError, OSError, ValueError, TypeError):
        return repli


def lire(nac_db: Path, netstats: Path, hote: str, maintenant: float) -> Releve:
    try:
        lignes = _lignes(Path(nac_db))
    except (sqlite3.Error, OSError) as e:
        return _inaccessible(f"NAC illisible : {type(e).__name__}")
    ifaces: set = set()
    try:
        data = json.loads(Path(netstats).read_text(encoding="utf-8"))
        brut = data.get("interfaces") if isinstance(data, dict) else None
        if isinstance(brut, dict):
            ifaces = {k for k in brut if suffixe_valide(k)}
    except (OSError, ValueError):
        pass  # les débits sont accessoires : l'inventaire du NAC suffit
    noeud = f"node:{hote}"
    entites: Dict[str, Dict[str, Any]] = {noeud: {"id": noeud, "label": hote, "attributes": {}}}
    rels: Dict[tuple, Dict[str, Any]] = {}
    aujourdhui = jour(maintenant)

    def rel(src: str, dst: str, typ: str, vu: str) -> None:
        rels[(src, dst, typ)] = {"src": src, "dst": dst, "type": typ, "evidence_type": "observed",
                                 "confidence": 1.0, "justification": f"inventaire du NAC, vu le {vu}",
                                 "source_module": "nac"}

    def interface(nom: str) -> str:
        i = f"interface:{nom}"
        if i not in entites:
            entites[i] = {"id": i, "label": nom, "attributes": {}}
            rel(i, noeud, "BELONGS_TO", aujourdhui)
        return i

    for nom in ifaces:
        interface(nom)
    for r in lignes:
        mac = str(r["mac"] or "").strip().lower()
        if not _MAC.match(mac):
            continue
        vu = _jour_sur(r["last_seen"], aujourdhui)
        d = f"device:{mac}"
        attrs = {k: r[k] for k in ("hostname", "device_type", "oui_vendor") if r[k]}
        attrs["mac_random"] = bool(r["mac_random"])
        # Date du NAC au jour près (UTC) : la vue du graphe trie les appareils dessus ; le jour seul garde
        # l'empreinte stable entre deux contacts d'une même journée. Absente si last_seen est corrompu.
        vu_nac = _jour_sur(r["last_seen"], "")
        if vu_nac:
            attrs["vu_nac"] = vu_nac
        adresse = _ip(r["ip"]) if r["ip"] else None
        if adresse and suffixe_valide(adresse):
            attrs["ip"] = adresse
        entites[d] = {"id": d, "label": (r["hostname"] or mac), "attributes": attrs}
        nom_if = (r["interface"] or "").strip()
        if nom_if and suffixe_valide(nom_if):
            rel(d, interface(nom_if), "CONNECTS_TO", vu)
        if adresse and suffixe_valide(adresse):
            i = f"ip:{adresse}"
            entites[i] = {"id": i, "label": adresse, "attributes": {}}
            rel(i, d, "BELONGS_TO", vu)
        zone = (r["zone"] or "").strip()
        if zone and suffixe_valide(zone):
            n = f"network:{zone}"
            entites[n] = {"id": n, "label": zone, "attributes": {}}
            rel(d, n, "BELONGS_TO", vu)
    liste_e, liste_r = list(entites.values()), list(rels.values())
    return Releve(source=SOURCE, etat="ok", entites=liste_e, relations=liste_r,
                  empreinte=empreinte(liste_e, liste_r))
