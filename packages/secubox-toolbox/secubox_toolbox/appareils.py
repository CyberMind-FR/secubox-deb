# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Rattache une identité de client (pair WireGuard, client du portail) à son
APPAREIL RÉEL, celui que le NAC a vu sur le réseau (#2415).

Une identité du Toolbox est une empreinte de clé ou d'adresse : un même matériel
peut en avoir plusieurs (profil régénéré, bascule de niveau), et une identité sans
tunnel n'est pas un appareil. Ici on ne rattache que sur PREUVE : l'adresse locale
d'un pair (point d'accès du tunnel) ou d'un client du portail égale à l'adresse
d'un appareil connu du NAC. Rien d'autre n'est deviné. La clé rendue est un
condensat de l'adresse MAC : la MAC elle-même ne sort jamais.
"""
from __future__ import annotations

import hashlib
import ipaddress
import sqlite3
import time
from pathlib import Path

NAC_DB = Path("/var/lib/secubox/nac/devices.db")
_TTL = 30.0
_cache: dict = {"t": 0.0, "d": {}}


def _prive(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not a.is_loopback and not a.is_link_local


def par_ip() -> dict[str, dict]:
    """{adresse locale: {cle, nom, fabricant, os}} depuis la base du NAC (lecture seule)."""
    now = time.time()
    if now - _cache["t"] < _TTL and _cache["d"]:
        return _cache["d"]
    out: dict[str, dict] = {}
    try:
        with sqlite3.connect(f"file:{NAC_DB}?mode=ro", uri=True, timeout=1.0) as c:
            for mac, ip, host, fab, os_, typ in c.execute(
                    "SELECT mac, ip, hostname, oui_vendor, os, device_type FROM devices WHERE ip IS NOT NULL AND ip != ''"):
                info = {"cle": hashlib.sha256(str(mac).lower().encode()).hexdigest()[:12],
                        "nom": (host or "").strip() or (typ if typ and typ != "unknown" else ""),
                        "fabricant": (fab or "").strip(), "os": (os_ or "").strip()}
                for a in str(ip).replace(",", " ").split():
                    if _prive(a):
                        out[a] = info
    except Exception:
        return _cache["d"]          # base absente ou verrouillée : on garde le dernier état
    _cache["t"], _cache["d"] = now, out
    return out


def rattacher(candidats: list[str | None]) -> dict | None:
    """Premier appareil du NAC dont l'adresse locale figure parmi les candidats."""
    base = par_ip()
    for ip in candidats:
        if ip and ip in base:
            return base[ip]
    return None
