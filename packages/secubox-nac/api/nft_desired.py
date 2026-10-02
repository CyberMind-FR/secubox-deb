# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: NAC — état voulu des ensembles nftables (#1766)
CyberMind — https://cybermind.fr

L'API tourne sans privilège (NoNewPrivileges, pas de capacité) : elle ne peut pas
parler à nftables. Elle écrit ici l'ÉTAT VOULU des ensembles de MAC ; le service root
`secubox-nac-apply` (déclenché par une unité .path) le valide et l'applique. Ce fichier
est aussi la source des lectures (liste d'une zone, appartenance) : plus besoin de
`nft list` en `secubox`.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
from pathlib import Path

DESIRED = Path(os.environ.get("NAC_NFT_DESIRED", "/var/lib/secubox/nac/nft-desired.json"))
SETS = ("blocked", "lan_allowed", "lxc_zone", "iot_zone", "guest_zone", "quarantine_zone")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def canon(mac: str) -> str | None:
    """MAC en minuscules, ou None si ce n'en est pas une (jamais d'injection dans nft)."""
    m = (mac or "").strip().lower()
    return m if MAC_RE.match(m) else None


def _lire() -> dict:
    try:
        d = json.loads(DESIRED.read_text())
    except (OSError, ValueError):
        return {}
    return {s: sorted({m for m in d.get(s, []) if canon(m)}) for s in SETS} if isinstance(d, dict) else {}


def _ecrire(d: dict) -> None:
    DESIRED.parent.mkdir(parents=True, exist_ok=True)
    tmp = DESIRED.with_name(DESIRED.name + ".tmp")
    tmp.write_text(json.dumps({s: sorted(d.get(s, [])) for s in SETS}, indent=1))
    os.replace(tmp, DESIRED)        # atomique : l'unité .path ne voit jamais un fichier à moitié écrit


class _Verrou:
    def __enter__(self):
        DESIRED.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(DESIRED.with_name(DESIRED.name + ".lock"), "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def members(set_name: str) -> list[str]:
    return _lire().get(set_name, []) if set_name in SETS else []


def add(set_name: str, mac: str) -> bool:
    m = canon(mac)
    if set_name not in SETS or not m:
        return False
    try:
        with _Verrou():
            d = _lire()
            if m not in d.get(set_name, []):
                d.setdefault(set_name, []).append(m)
                _ecrire(d)
        return True
    except OSError:
        return False


def remove(set_name: str, mac: str) -> bool:
    m = canon(mac)
    if set_name not in SETS or not m:
        return False
    try:
        with _Verrou():
            d = _lire()
            if m in d.get(set_name, []):
                d[set_name].remove(m)
                _ecrire(d)
        return True
    except OSError:
        return False


def resync() -> bool:
    """Réécrit l'état courant pour déclencher secubox-nac-apply (unité .path)."""
    try:
        with _Verrou():
            _ecrire(_lire())
        return True
    except OSError:
        return False
