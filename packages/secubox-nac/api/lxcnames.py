# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Noms des conteneurs LXC (#2445) : nos modules, dont on connaît le nom même sans DNS ni bail.

Le fichier est écrit par le petit service root `secubox-nac-lxc-names` (les dossiers de conteneurs sont fermés au compte du NAC). Absent ou
illisible : aucun nom, jamais d'erreur."""
from __future__ import annotations

import json
import os

CHEMIN = os.environ.get("SBX_LXC_NOMS", "/var/lib/secubox/nac/conteneurs.json")
_CACHE: dict = {"mtime": None, "data": {"ips": {}, "macs": {}}}


def charger(chemin: str | None = None) -> dict:
    chemin = chemin or CHEMIN
    try:
        m = os.stat(chemin).st_mtime
        if _CACHE["mtime"] == (chemin, m):
            return _CACHE["data"]
        with open(chemin, encoding="utf-8") as f:
            d = json.load(f)
        data = {"ips": {str(k): str(v) for k, v in (d.get("ips") or {}).items()}, "macs": {str(k).lower(): str(v) for k, v in (d.get("macs") or {}).items()}}
        _CACHE.update(mtime=(chemin, m), data=data)
        return data
    except (OSError, ValueError, AttributeError):
        return {"ips": {}, "macs": {}}


def nom(ip: str = "", mac: str = "", chemin: str | None = None) -> str | None:
    d = charger(chemin)
    return d["macs"].get((mac or "").lower()) or d["ips"].get(ip or "")
