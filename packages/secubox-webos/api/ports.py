# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webos — LES PORTS QUE CETTE BOX PUBLIE POUR LE RELAIS DU MAÎTRE (#3154).

Un module qui doit être joignable de l'extérieur sur un port brut (média d'une visio, par exemple) dépose
/var/lib/secubox/ports-publics.d/<module>.json ; le maître du maillage les lit par /public/ports et les relaie.
Les fichiers sont une entrée non fiable : tout est validé, un fichier illisible est ignoré.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

DOSSIER = Path("/var/lib/secubox/ports-publics.d")
MAX_ENTREES = 16
_MODULE = re.compile(r"[a-z0-9-]{1,32}")


def lire() -> list[dict]:
    """Ports publiés, validés, triés par (proto, port), au plus MAX_ENTREES."""
    trouves: set[tuple[str, int, str]] = set()
    try:
        fichiers = sorted(DOSSIER.glob("*.json"))
    except OSError:
        return []
    for f in fichiers:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        module, liste = d.get("module"), d.get("ports")
        if not isinstance(module, str) or not _MODULE.fullmatch(module) or not isinstance(liste, list):
            continue
        for p in liste:
            if not isinstance(p, dict):
                continue
            proto, port = p.get("proto"), p.get("port")
            if proto in ("tcp", "udp") and type(port) is int and 1024 <= port <= 65535:
                trouves.add((proto, port, module))
    return [{"proto": pr, "port": po, "module": mo} for pr, po, mo in sorted(trouves)[:MAX_ENTREES]]
