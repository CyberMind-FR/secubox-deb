# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: DevWatch — révisions des modules de la box (local).

Complément LOCAL au pouls GitHub : l'état de révision des paquets `secubox-*`
installés — version courante et dernier développement (première puce du
changelog) — trié du plus récemment CONSTRUIT au plus ancien. Tout est lu sur
le disque (dpkg + changelogs, en lecture seule) ; aucune commande, aucun réseau.
"""
from __future__ import annotations

import gzip
import os
import re

DPKG_STATUS = "/var/lib/dpkg/status"
DOC = "/usr/share/doc"

# On raccourcit la version Debian pour l'affichage : « 1.0.203-1~bookworm1 »
# n'intéresse personne au-delà de « 1.0.203 ».
_REV = re.compile(r"-\d+~.*$")
_PUCE = re.compile(r"^\s*\*\s*(.+)$", re.M)
_SIG = re.compile(r"^ -- .*?>  (.+)$", re.M)


def _version_courte(v: str) -> str:
    return _REV.sub("", (v or "").strip())


def _stanza(pkg: str) -> tuple[str, str]:
    """(dernier développement, date) depuis la 1re strophe du changelog."""
    path = os.path.join(DOC, pkg, "changelog.Debian.gz")
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            txt = f.read(4000)
    except Exception:
        return "", ""
    dev, date = "", ""
    m = _PUCE.search(txt)
    if m:
        dev = re.sub(r"\s+", " ", m.group(1)).strip()[:140]
    d = _SIG.search(txt)
    if d:
        date = d.group(1).strip()
    return dev, date


def _installes() -> dict:
    """Paquets secubox-* réellement installés → {nom: version}."""
    out: dict[str, str] = {}
    cur: dict = {}

    def flush():
        n = cur.get("name", "")
        if (n.startswith("secubox-") and cur.get("version")
                and "installed" in cur.get("status", "") and "not-installed" not in cur.get("status", "")):
            out[n] = cur["version"]

    try:
        with open(DPKG_STATUS, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("Package:"):
                    cur = {"name": line.split(":", 1)[1].strip()}
                elif line.startswith("Version:"):
                    cur["version"] = line.split(":", 1)[1].strip()
                elif line.startswith("Status:"):
                    cur["status"] = line.split(":", 1)[1].strip()
                elif line.strip() == "":
                    flush()
                    cur = {}
        flush()
    except Exception:
        return out
    return out


def scan(limit: int = 24) -> list:
    """Modules `secubox-*`, du plus récemment construit au plus ancien.

    Le mtime du changelog installé ≈ l'instant de construction du paquet : c'est
    notre « dernier développement » sans avoir à parser toutes les dates.
    """
    pkgs = _installes()
    rows = []
    for name, ver in pkgs.items():
        mt = 0.0
        try:
            mt = os.path.getmtime(os.path.join(DOC, name, "changelog.Debian.gz"))
        except Exception:
            pass
        rows.append((name, ver, mt))
    rows.sort(key=lambda r: r[2], reverse=True)

    out = []
    for name, ver, mt in rows[:limit]:
        dev, date = _stanza(name)
        out.append({
            "name": name[len("secubox-"):],   # webos, radio, bbs…
            "pkg": name,
            "version": _version_courte(ver),
            "dev": dev,
            "date": date,
            "built": int(mt),
        })
    return {"total": len(pkgs), "modules": out}
