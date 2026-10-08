# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: metrics :: historique de la memoire de la box (#2146).

Un releve toutes les 5 minutes (timer secubox-metrics-memoire), garde 7 jours en JSON-lignes.
Il surveille surtout la memoire NOYAU non recuperable (`SUnreclaim`) : sur gk2 elle est montee a
4,2 Go sans que rien ne le releve, jusqu'a saturer la box. Les seuils sont des parts de la RAM
(la meme regle vaut pour une box 2 Go et une box 8 Go) ; la CROISSANCE est signalee avant le seuil.

Stdlib seule : le releve ne doit pas peser sur la box qu'il surveille.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

FICHIER = Path("/var/lib/secubox/metrics/memoire.jsonl")
RETENTION_S = 7 * 86400
PAS_S = 300

# Seuils, en part de la RAM : memoire noyau non recuperable, memoire disponible, swap utilise.
SEUIL_NOYAU = 0.10
SEUIL_DISPONIBLE = 0.06
SEUIL_SWAP = 0.25
# Croissance du noyau jugee anormale (Mo/h) sur au moins une demi-heure de releves.
SEUIL_CROISSANCE_MB_H = 50.0
MIN_POINTS = 6


def _meminfo(chemin: str) -> dict:
    out = {}
    with open(chemin) as f:
        for ligne in f:
            p = ligne.split()
            if len(p) >= 2 and p[1].isdigit():
                out[p[0].rstrip(":")] = int(p[1])
    return out


def releve(meminfo: str = "/proc/meminfo", loadavg: str = "/proc/loadavg",
           maintenant: Optional[float] = None) -> dict:
    """Un releve en Mo (le noyau donne des ko)."""
    m = _meminfo(meminfo)
    total = m.get("MemTotal", 0)
    dispo = m.get("MemAvailable", m.get("MemFree", 0))
    try:
        load1 = float(open(loadavg).read().split()[0])
    except (OSError, ValueError, IndexError):
        load1 = 0.0
    return {
        "t": int(maintenant if maintenant is not None else time.time()),
        "total_mb": total // 1024,
        "used_mb": total // 1024 - dispo // 1024,
        "avail_mb": dispo // 1024,
        "slab_unrecl_mb": m.get("SUnreclaim", 0) // 1024,
        "slab_recl_mb": m.get("SReclaimable", 0) // 1024,
        "swap_mb": max(0, m.get("SwapTotal", 0) - m.get("SwapFree", 0)) // 1024,
        "load1": load1,
    }


def croissance_mb_h(serie: list, cle: str) -> Optional[float]:
    """Pente moyenne (Mo/h) de `cle` entre le premier et le dernier point ; None sous trois points."""
    pts = [(r["t"], r[cle]) for r in serie if cle in r and "t" in r]
    if len(pts) < 3 or pts[-1][0] <= pts[0][0]:
        return None
    return (pts[-1][1] - pts[0][1]) / ((pts[-1][0] - pts[0][0]) / 3600.0)


def alertes(r: dict, serie: Optional[list] = None) -> list:
    """Messages d'alerte pour ce releve (et la croissance sur `serie`, releves recents)."""
    out = []
    total = r.get("total_mb") or 1
    if r.get("slab_unrecl_mb", 0) > SEUIL_NOYAU * total:
        out.append(f"memoire noyau non recuperable a {r['slab_unrecl_mb']} Mo "
                   f"({100 * r['slab_unrecl_mb'] // total} % de la RAM) : fuite probable")
    if r.get("avail_mb", total) < SEUIL_DISPONIBLE * total:
        out.append(f"memoire disponible a {r['avail_mb']} Mo ({100 * r['avail_mb'] // total} % de la RAM)")
    if r.get("swap_mb", 0) > SEUIL_SWAP * total:
        out.append(f"swap utilise a {r['swap_mb']} Mo")
    if serie and len(serie) >= MIN_POINTS:
        g = croissance_mb_h(serie, "slab_unrecl_mb")
        if g is not None and g > SEUIL_CROISSANCE_MB_H:
            out.append(f"memoire noyau non recuperable croit de {g:.0f} Mo/h")
    return out


def lire_historique(chemin: Path = FICHIER, depuis: float = 0) -> list:
    """Les releves plus recents que `depuis` ; une ligne cassee est ignoree, un fichier absent rend []."""
    out = []
    try:
        with open(chemin) as f:
            for ligne in f:
                try:
                    r = json.loads(ligne)
                except ValueError:
                    continue
                if isinstance(r, dict) and r.get("t", 0) >= depuis:
                    out.append(r)
    except OSError:
        return []
    return out


def ajoute(r: dict, chemin: Path = FICHIER, maintenant: Optional[float] = None) -> None:
    """Ajoute un releve et ecarte ce qui a plus de RETENTION_S (reecriture atomique)."""
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    maintenant = maintenant if maintenant is not None else time.time()
    gardes = lire_historique(chemin, depuis=maintenant - RETENTION_S) + [r]
    tmp = chemin.with_name(chemin.name + ".tmp")
    tmp.write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in gardes))
    os.replace(tmp, chemin)


def vue(heures: float = 24, chemin: Path = FICHIER, maintenant: Optional[float] = None) -> dict:
    """Ce que sert l'API : la serie des `heures` dernieres heures (bornee a 7 jours), les alertes, la croissance."""
    maintenant = maintenant if maintenant is not None else time.time()
    heures = max(0.1, min(float(heures), RETENTION_S / 3600))
    serie = lire_historique(chemin, depuis=maintenant - heures * 3600)
    return {
        "serie": serie,
        "alertes": alertes(serie[-1], serie[-36:]) if serie else [],
        "croissance_noyau_mb_h": croissance_mb_h(serie[-36:], "slab_unrecl_mb"),
        "pas_s": PAS_S,
    }


def main(argv=None) -> int:
    """Point d'entree du timer : un releve, ajoute a l'historique ; les alertes vont au journal."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--meminfo", default="/proc/meminfo")
    ap.add_argument("--loadavg", default="/proc/loadavg")
    ap.add_argument("--fichier", default=str(FICHIER))
    a = ap.parse_args(argv)
    r = releve(a.meminfo, a.loadavg)
    ajoute(r, Path(a.fichier))
    recents = lire_historique(Path(a.fichier), depuis=r["t"] - 3 * 3600)
    for msg in alertes(r, recents):
        print(f"ALERTE memoire : {msg}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
